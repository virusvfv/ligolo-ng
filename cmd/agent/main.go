package main

import (
	"context"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"github.com/hashicorp/yamux"
	"github.com/nicocha30/ligolo-ng/pkg/agent/neterror"
	"github.com/nicocha30/ligolo-ng/pkg/agent/smartping"
	"github.com/nicocha30/ligolo-ng/pkg/protocol"
	"github.com/nicocha30/ligolo-ng/pkg/relay"
	"github.com/sirupsen/logrus"
	"golang.org/x/net/http2"
	goproxy "golang.org/x/net/proxy"
	"io"
	"net"
	"net/http"
	"net/url"
	"nhooyr.io/websocket"
	"os"
	"os/user"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"
)

var listenerConntrack map[int32]net.Conn
var listenerMap map[int32]net.Listener
var connTrackID int32
var listenerID int32

func main() {
	var tlsConfig tls.Config
	var ignoreCertificate = flag.Bool("ignore-cert", false, "ignore TLS certificate validation (dangerous), only for debug purposes")
	var verbose = flag.Bool("v", false, "enable verbose mode")
	var ech = flag.Bool("ech", false, "enable verbose mode")
	var retry = flag.Bool("retry", false, "auto-retry on error")
	var retryTime = flag.Int("retryTime", 5, "auto-retry timeout in sec")
	var socksProxy = flag.String("proxy", "", "socks5/http proxy address (ip:port) "+
		"in case of websockets it could be proxy URL: http://admin:secret@127.0.0.1:8080")
	var socksUser = flag.String("socks-user", "", "socks5 username")
	var socksPass = flag.String("socks-pass", "", "socks5 password")
	var serverAddr = flag.String("connect", "", "the target (domain:port)")
	var userAgent = flag.String("ua", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "+
		"AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36", "http User-Agent")

	flag.Parse()

	logrus.SetReportCaller(*verbose)

	if *verbose {
		logrus.SetLevel(logrus.DebugLevel)
	}

	if strings.Contains(*serverAddr, "https://") {
		//websocket connection
		host, _, err := net.SplitHostPort(strings.Replace(*serverAddr, "https://", "", 1))
		if err != nil {
			logrus.Fatal("invalid https address, please use https://host:port")
		}
		tlsConfig.ServerName = host
		if *ignoreCertificate {
			logrus.Warn("warning, certificate validation disabled")
			tlsConfig.InsecureSkipVerify = true
		}
	} else {
		//direct connection
		host, _, err := net.SplitHostPort(*serverAddr)
		if err != nil {
			logrus.Fatal("invalid connect address, please use host:port")
		}
		tlsConfig.ServerName = host
		if *ignoreCertificate {
			logrus.Warn("warning, certificate validation disabled")
			tlsConfig.InsecureSkipVerify = true
		}
	}

	var conn net.Conn

	listenerConntrack = make(map[int32]net.Conn)
	listenerMap = make(map[int32]net.Listener)

	for {
		var err error
		if strings.Contains(*serverAddr, "https://") || strings.Contains(*serverAddr, "wss://") {
			*serverAddr = strings.Replace(*serverAddr, "https://", "wss://", 1)
			//websocket
			err = wsconnect(&tlsConfig, *serverAddr, *socksProxy, *userAgent, *ech)
		} else {
			//direct connection
			if *socksProxy != "" {
				if _, _, err := net.SplitHostPort(*socksProxy); err != nil {
					logrus.Fatal("invalid socks5 address, please use host:port")
				}
				conn, err = sockDial(*serverAddr, *socksProxy, *socksUser, *socksPass)
			} else {
				conn, err = net.Dial("tcp", *serverAddr)
			}
			if err == nil {
				err = connect(conn, &tlsConfig)
			}
		}

		logrus.Errorf("Connection error: %v", err)
		if *retry {
			logrus.Infof("Retrying in %d seconds.", *retryTime)
			time.Sleep(time.Duration(*retryTime) * time.Second)
		} else {
			logrus.Fatal(err)
		}
	}
}

func sockDial(serverAddr string, socksProxy string, socksUser string, socksPass string) (net.Conn, error) {
	proxyDialer, err := goproxy.SOCKS5("tcp", socksProxy, &goproxy.Auth{
		User:     socksUser,
		Password: socksPass,
	}, goproxy.Direct)
	if err != nil {
		logrus.Fatalf("socks5 error: %v", err)
	}
	return proxyDialer.Dial("tcp", serverAddr)
}

func DoHGetIPECHKeys(servername string, proxystr string) ([]tls.ECHConfig, string) {
	//Make DoH query for ECH keys and IP address of domain to cloudflare DoH provider
	//To reduce https connection to cloudflare we use HTTP2 multiplexing (2 http in a row)
	//
	DoHProvider := "chrome.cloudflare-dns.com"

	proxyUrl, err := url.Parse(proxystr)
	if err != nil || proxystr == "" {
		proxyUrl = nil
	}
	httpTransport := &http.Transport{
		Proxy:           http.ProxyURL(proxyUrl),
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	err = http2.ConfigureTransport(httpTransport) // upgrade to HTTP2, while keeping http.Transport
	if err != nil {
		return nil, ""
	}

	dohstr := fmt.Sprintf("https://%s/dns-query?name=%s&type=TYPE65", DoHProvider, "crypto.cloudflare.com") //for ECH keys
	dohstr2 := fmt.Sprintf("https://%s/dns-query?name=%s&type=A", DoHProvider, servername)                  //for A record (Ip addr)
	httpclient := http.Client{Timeout: time.Duration(10) * time.Second, Transport: httpTransport}
	httpreq, _ := http.NewRequest("GET", dohstr, nil)
	httpreq2, _ := http.NewRequest("GET", dohstr2, nil)
	httpreq.Header.Add("accept", "application/dns-json")
	httpreq2.Header.Add("accept", "application/dns-json")
	response, err := httpclient.Do(httpreq)
	response2, err := httpclient.Do(httpreq2)

	if err != nil {
		return nil, ""
	}
	respBody, _ := io.ReadAll(response.Body)
	respBody2, _ := io.ReadAll(response2.Body)
	respBodystr := strings.Replace(string(respBody), " ", "", -1)
	respBody2str := strings.Replace(string(respBody2), " ", "", -1)

	//parse ECH keys
	re := regexp.MustCompile("0005(\\d\\d\\d\\d)0045")
	refind := re.FindAllStringSubmatch(respBodystr, -1)

	var echbytes []byte
	var ipaddr string

	if refind != nil {
		//dehex, err := hex.DecodeString(refind[0][1])
		if err == nil {
			dohLen, _ := strconv.ParseInt(refind[0][1], 16, 64)
			restr := fmt.Sprintf("0005\\d\\d\\d\\d0045[0-9a-f]{%d}", dohLen*2-4)
			re, _ = regexp.Compile(restr)
			refind := re.FindString(respBodystr)
			if refind != "" {
				ech0 := refind[8:]
				echbytes, _ = hex.DecodeString(ech0)
			}
		}
	}
	//parse IP in json response: Answer":[{"name":"www.site.ru","type":1,"TTL":300,"data":"104.21.51.183"}
	re = regexp.MustCompile("\"data\":\"([0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3})\"\\}")
	refind = re.FindAllStringSubmatch(respBody2str, -1)
	if refind != nil {
		ipaddr = refind[0][1]
	}

	if echbytes != nil {
		echConfigsList, err := tls.UnmarshalECHConfigs(echbytes)
		if err != nil {
			return nil, ipaddr
		}
		return echConfigsList, ipaddr
	} else {
		return nil, ipaddr
	}
}

func wsconnect(config *tls.Config, wsaddr string, proxystr string, useragent string, useECH bool) error {
	var ipaddr string
	var servername string
	var serverport string
	var echConfigsList []tls.ECHConfig

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*20)
	defer cancel()

	serverUrl, err := url.Parse(wsaddr)
	if err == nil {
		servername = serverUrl.Hostname()
		serverport = serverUrl.Port()
	}

	if useECH {
		echConfigsList, ipaddr = DoHGetIPECHKeys(servername, proxystr)
		if echConfigsList != nil || ipaddr != "" {
			logrus.Info("Got ECH keys. Using TLS1.3 ECH...")
			logrus.Printf("Resolved IP address is %s", ipaddr)
			config.ECHEnabled = true
			config.ClientECHConfigs = echConfigsList
			config.MinVersion = tls.VersionTLS12
		} else {
			logrus.Info("Error with ECH keys. Using plaintext SNI :( ...")
			config.ECHEnabled = false
			config.MinVersion = tls.VersionTLS11
		}
	}

	//proxystr = "http://admin:secret@127.0.0.1:8080"
	proxyUrl, err := url.Parse(proxystr)
	if err != nil || proxystr == "" {
		proxyUrl = nil
	}

	//small hack to disable system DNS requests for target domain
	stdDialer := &net.Dialer{
		Timeout:   20 * time.Second,
		KeepAlive: 60 * time.Second,
	}
	httpTransport := &http.Transport{
		MaxIdleConns:    http.DefaultMaxIdleConnsPerHost,
		TLSClientConfig: config,
		Proxy:           http.ProxyURL(proxyUrl),
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			//logrus.Printf("Debug: addr is %s", addr)
			if addr == (servername + ":" + serverport) {
				addr = ipaddr + ":" + serverport
			}
			return stdDialer.DialContext(ctx, network, addr)
		},
	}

	httpClient := &http.Client{Transport: httpTransport}
	httpheader := &http.Header{}
	httpheader.Add("User-Agent", useragent)

	wsConn, _, err := websocket.Dial(ctx, wsaddr, &websocket.DialOptions{HTTPClient: httpClient, HTTPHeader: *httpheader})
	if err != nil {
		return err
	}

	netctx, cancel := context.WithTimeout(context.Background(), time.Hour*999999)
	netConn := websocket.NetConn(netctx, wsConn, websocket.MessageBinary)
	defer cancel()
	yamuxConn, err := yamux.Server(netConn, yamux.DefaultConfig())
	if err != nil {
		return err
	}

	logrus.Info("websocket connection established")
	for {
		conn, err := yamuxConn.Accept()
		if err != nil {
			return err
		}
		go handleConn(conn)
	}
	//return nil
}

func connect(conn net.Conn, config *tls.Config) error {
	tlsConn := tls.Client(conn, config)

	yamuxConn, err := yamux.Server(tlsConn, yamux.DefaultConfig())
	if err != nil {
		return err
	}

	logrus.WithFields(logrus.Fields{"addr": tlsConn.RemoteAddr()}).Info("Connection established")

	for {
		conn, err := yamuxConn.Accept()
		if err != nil {
			return err
		}
		go handleConn(conn)
	}
}

// Listener is the base class implementing listener sockets for Ligolo
type Listener struct {
	net.Listener
}

// NewListener register a new listener
func NewListener(network string, addr string) (Listener, error) {
	lis, err := net.Listen(network, addr)
	if err != nil {
		return Listener{}, err
	}
	return Listener{lis}, nil
}

// ListenAndServe fill new listener connections to a channel
func (s *Listener) ListenAndServe(connTrackChan chan int32) error {
	for {
		conn, err := s.Accept()
		if err != nil {
			return err
		}
		connTrackID++
		connTrackChan <- connTrackID
		listenerConntrack[connTrackID] = conn
	}
}

// Close request the main listener to exit
func (s *Listener) Close() error {
	return s.Listener.Close()
}

func handleConn(conn net.Conn) {
	decoder := protocol.NewDecoder(conn)
	if err := decoder.Decode(); err != nil {
		panic(err)
	}

	e := decoder.Envelope.Payload
	switch decoder.Envelope.Type {

	case protocol.MessageConnectRequest:
		connRequest := e.(protocol.ConnectRequestPacket)
		encoder := protocol.NewEncoder(conn)

		logrus.Debugf("Got connect request to %s:%d", connRequest.Address, connRequest.Port)
		var network string
		if connRequest.Transport == protocol.TransportTCP {
			network = "tcp"
		} else {
			network = "udp"
		}
		if connRequest.Net == protocol.Networkv4 {
			network += "4"
		} else {
			network += "6"
		}

		var d net.Dialer
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		targetConn, err := d.DialContext(ctx, network, fmt.Sprintf("%s:%d", connRequest.Address, connRequest.Port))
		defer cancel()

		var connectPacket protocol.ConnectResponsePacket
		if err != nil {

			var serr syscall.Errno
			if errors.As(err, &serr) {
				// Magic trick ! If the error syscall indicate that the system responded, send back a RST packet!
				if neterror.HostResponded(serr) {
					connectPacket.Reset = true
				}
			}

			connectPacket.Established = false
		} else {
			connectPacket.Established = true
		}
		if err := encoder.Encode(protocol.Envelope{
			Type:    protocol.MessageConnectResponse,
			Payload: connectPacket,
		}); err != nil {
			logrus.Fatal(err)
		}
		if connectPacket.Established {
			relay.StartRelay(targetConn, conn)
		}
	case protocol.MessageHostPingRequest:
		pingRequest := e.(protocol.HostPingRequestPacket)
		encoder := protocol.NewEncoder(conn)

		pingResponse := protocol.HostPingResponsePacket{Alive: smartping.TryResolve(pingRequest.Address)}

		if err := encoder.Encode(protocol.Envelope{
			Type:    protocol.MessageHostPingResponse,
			Payload: pingResponse,
		}); err != nil {
			logrus.Fatal(err)
		}
	case protocol.MessageInfoRequest:
		var username string
		encoder := protocol.NewEncoder(conn)
		hostname, err := os.Hostname()
		if err != nil {
			hostname = "UNKNOWN"
		}

		userinfo, _ := user.Current()
		if err != nil {
			username = "Unknown"
		} else {
			username = userinfo.Username
		}

		netifaces, err := net.Interfaces()
		if err != nil {
			logrus.Error("could not get network interfaces")
			return
		}
		infoResponse := protocol.InfoReplyPacket{
			Name:       fmt.Sprintf("%s@%s", username, hostname),
			Interfaces: protocol.NewNetInterfaces(netifaces),
		}

		if err := encoder.Encode(protocol.Envelope{
			Type:    protocol.MessageInfoReply,
			Payload: infoResponse,
		}); err != nil {
			logrus.Fatal(err)
		}
	case protocol.MessageListenerCloseRequest:
		// Request to close a listener
		closeRequest := e.(protocol.ListenerCloseRequestPacket)
		encoder := protocol.NewEncoder(conn)

		var err error
		if lis, ok := listenerMap[closeRequest.ListenerID]; ok {
			err = lis.Close()
		} else {
			err = errors.New("invalid listener id")
		}

		listenerResponse := protocol.ListenerCloseResponsePacket{
			Err: err != nil,
		}
		if err != nil {
			listenerResponse.ErrString = err.Error()
		}

		if err := encoder.Encode(protocol.Envelope{
			Type:    protocol.MessageListenerCloseResponse,
			Payload: listenerResponse,
		}); err != nil {
			logrus.Error(err)
		}

	case protocol.MessageListenerRequest:
		listenRequest := e.(protocol.ListenerRequestPacket)
		encoder := protocol.NewEncoder(conn)
		connTrackChan := make(chan int32)
		stopChan := make(chan error)

		listener, err := NewListener(listenRequest.Network, listenRequest.Address)
		if err != nil {
			listenerResponse := protocol.ListenerResponsePacket{
				ListenerID: 0,
				Err:        true,
				ErrString:  err.Error(),
			}
			if err := encoder.Encode(protocol.Envelope{
				Type:    protocol.MessageListenerResponse,
				Payload: listenerResponse,
			}); err != nil {
				logrus.Error(err)
			}
			return
		}

		listenerResponse := protocol.ListenerResponsePacket{
			ListenerID: listenerID,
			Err:        false,
			ErrString:  "",
		}
		listenerMap[listenerID] = listener.Listener
		listenerID++

		if err := encoder.Encode(protocol.Envelope{
			Type:    protocol.MessageListenerResponse,
			Payload: listenerResponse,
		}); err != nil {
			logrus.Error(err)
		}

		go func() {
			if err := listener.ListenAndServe(connTrackChan); err != nil {
				stopChan <- err
			}
		}()
		defer listener.Close()

		for {
			var bindResponse protocol.ListenerBindReponse
			select {
			case err := <-stopChan:
				logrus.Error(err)
				bindResponse = protocol.ListenerBindReponse{
					SockID:    0,
					Err:       true,
					ErrString: err.Error(),
				}
			case connTrackID := <-connTrackChan:
				bindResponse = protocol.ListenerBindReponse{
					SockID: connTrackID,
					Err:    false,
				}
			}

			if err := encoder.Encode(protocol.Envelope{
				Type:    protocol.MessageListenerBindResponse,
				Payload: bindResponse,
			}); err != nil {
				logrus.Error(err)
			}

			if bindResponse.Err {
				break
			}

		}
	case protocol.MessageListenerSockRequest:
		sockRequest := e.(protocol.ListenerSockRequestPacket)
		encoder := protocol.NewEncoder(conn)

		var sockResponse protocol.ListenerSockResponsePacket
		if _, ok := listenerConntrack[sockRequest.SockID]; !ok {
			// Handle error
			sockResponse.ErrString = "invalid or unexistant SockID"
			sockResponse.Err = true
		}

		if err := encoder.Encode(protocol.Envelope{
			Type:    protocol.MessageListenerSockResponse,
			Payload: sockResponse,
		}); err != nil {
			logrus.Fatal(err)
		}

		if sockResponse.Err {
			return
		}

		netConn := listenerConntrack[sockRequest.SockID]
		relay.StartRelay(netConn, conn)

	case protocol.MessageClose:
		os.Exit(0)

	}
}
