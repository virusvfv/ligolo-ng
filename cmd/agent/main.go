package main

import (
	"context"
	"crypto/tls"
	"encoding/hex"
	"flag"
	"fmt"
	"github.com/hashicorp/yamux"
	"github.com/nicocha30/ligolo-ng/pkg/agent"
	"github.com/sirupsen/logrus"
	"golang.org/x/net/http2"
	goproxy "golang.org/x/net/proxy"
	"io"
	"net"
	"net/http"
	"net/url"
	"nhooyr.io/websocket"
	"regexp"
	"strconv"
	"strings"
	"time"
)

func main() {
	var tlsConfig tls.Config
	var ignoreCertificate = flag.Bool("ignore-cert", false, "ignore TLS certificate validation (dangerous), only for debug purposes")
	var verbose = flag.Bool("v", false, "enable verbose mode")
	var ech = flag.Bool("ech", false, "enable verbose mode")
	var retry = flag.Int("retry", 0, "auto-retry on error with delay in sec. If 0 then no auto-retry")
	var socksProxy = flag.String("proxy", "", "proxy URL address (http://admin:secret@127.0.0.1:8080)"+
		" or socks://admin:secret@127.0.0.1:8080")
	var serverAddr = flag.String("connect", "", "the target (domain:port)")
	var userAgent = flag.String("ua", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "+
		"AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36", "http User-Agent")

	flag.Parse()

	logrus.SetReportCaller(*verbose)

	if *verbose {
		logrus.SetLevel(logrus.DebugLevel)
	}

	if *serverAddr == "" {
		logrus.Fatal("please, specify the target host user -connect host:port")
	}

	if strings.Contains(*serverAddr, "https://") {
		//websocket https connection
		host, _, err := net.SplitHostPort(strings.Replace(*serverAddr, "https://", "", 1))
		if err != nil {
			logrus.Info("There is no port in address string, assuming that port is 443")
			host = strings.Replace(*serverAddr, "https://", "", 1)
		}
		tlsConfig.ServerName = host
	} else if strings.Contains(*serverAddr, "http://") {
		//websocket http connection
		host, _, err := net.SplitHostPort(strings.Replace(*serverAddr, "http://", "", 1))
		if err != nil {
			logrus.Info("There is no port in address string, assuming that port is 80")
			host = strings.Replace(*serverAddr, "http://", "", 1)
		}
		tlsConfig.ServerName = host
	} else {
		//direct connection
		host, _, err := net.SplitHostPort(*serverAddr)
		if err != nil {
			logrus.Fatal("Invalid connect address, please use host:port")
		}
		tlsConfig.ServerName = host
	}

	if *ignoreCertificate {
		logrus.Warn("Warning, certificate validation disabled")
		tlsConfig.InsecureSkipVerify = true
	}

	var conn net.Conn

	for {
		var err error
		if strings.Contains(*serverAddr, "http://") || strings.Contains(*serverAddr, "https://") ||
			strings.Contains(*serverAddr, "wss://") || strings.Contains(*serverAddr, "ws://") {
			*serverAddr = strings.Replace(*serverAddr, "https://", "wss://", 1)
			*serverAddr = strings.Replace(*serverAddr, "http://", "ws://", 1)
			//websocket
			err = wsconnect(&tlsConfig, *serverAddr, *socksProxy, *userAgent, *ech)
		} else {
			if *socksProxy != "" {
				if strings.Contains(*socksProxy, "http://") {
					//TODO http proxy CONNECT
				} else {
					//suppose that scheme is socks:// or socks5://
					var proxyUrl *url.URL
					proxyUrl, err = url.Parse(*socksProxy)
					if err != nil {
						logrus.Fatal("invalid socks5 address, please use host:port")
					}
					if _, _, err = net.SplitHostPort(proxyUrl.Host); err != nil {
						logrus.Fatal("invalid socks5 address, please use socks://host:port")
					}
					pass, _ := proxyUrl.User.Password()
					conn, err = sockDial(*serverAddr, proxyUrl.Host, proxyUrl.User.Username(), pass)
					if err != nil {
						logrus.Errorf("Socks connection error: %v", err)
					} else {
						logrus.Infof("Connection to socks success.")
					}
				}
			} else {
				//direct connection
				conn, err = net.Dial("tcp", *serverAddr)
			}
			if err == nil {
				err = connect(conn, &tlsConfig)
			}
		}

		logrus.Errorf("Connection error: %v", err)
		if *retry > 0 {
			logrus.Infof("Retrying in %d seconds.", *retry)
			time.Sleep(time.Duration(*retry) * time.Second)
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
		go agent.HandleConn(conn)
	}
}

func wsconnect(config *tls.Config, wsaddr string, proxystr string, useragent string, useECH bool) error {
	var nossl bool
	var ipaddr string
	var servername string
	var serverport string
	var echConfigsList []tls.ECHConfig

	if strings.Contains(wsaddr, "ws://") {
		nossl = true
		useECH = false
	} else {
		nossl = false
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*20)
	defer cancel()

	serverUrl, err := url.Parse(wsaddr)
	if err == nil {
		servername = serverUrl.Hostname()
		serverport = serverUrl.Port()
	}

	//proxystr = "http://admin:secret@127.0.0.1:8080"
	proxyUrl, err := url.Parse(proxystr)
	if err != nil || proxystr == "" {
		proxyUrl = nil
	}
	stdDialer := &net.Dialer{
		Timeout:   20 * time.Second,
		KeepAlive: 60 * time.Second,
	}
	httpTransport := &http.Transport{}
	config.MinVersion = tls.VersionTLS10

	if useECH {
		echConfigsList, ipaddr = DoHGetIPECHKeys(servername, proxystr)
		if echConfigsList != nil && ipaddr != "" {
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
		//small hack to disable system DNS requests for target domain
		httpTransport = &http.Transport{
			MaxIdleConns:    http.DefaultMaxIdleConnsPerHost,
			TLSClientConfig: config,
			Proxy:           http.ProxyURL(proxyUrl),
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				if addr == (servername + ":" + serverport) {
					addr = ipaddr + ":" + serverport
				}
				return stdDialer.DialContext(ctx, network, addr)
			},
		}
	} else {
		config.ECHEnabled = false
		config.ClientECHConfigs = echConfigsList
		config.MinVersion = tls.VersionTLS10

		if nossl {
			httpTransport = &http.Transport{
				MaxIdleConns: http.DefaultMaxIdleConnsPerHost,
				Proxy:        http.ProxyURL(proxyUrl),
			}
		} else {
			httpTransport = &http.Transport{
				MaxIdleConns:    http.DefaultMaxIdleConnsPerHost,
				TLSClientConfig: config,
				Proxy:           http.ProxyURL(proxyUrl),
			}
		}

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

	logrus.Info("Websocket connection established")
	for {
		conn, err := yamuxConn.Accept()
		if err != nil {
			return err
		}
		go agent.HandleConn(conn)
	}
	//return nil
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

	//According https://community.cloudflare.com/t/early-hints-and-encrypted-client-hello-ech-are-currently-disabled-globally/567730
	// ECH currently disabled for customer domains ((((
	// But we can get ECH Keys for crypto.cloudflare.com domain and use it for encrypting ClientHello
	// After enabing ECH by Cloudflare switch next 2 codestring and use customer domain ECH keys
	dohstr := fmt.Sprintf("https://%s/dns-query?name=%s&type=TYPE65", DoHProvider, "crypto.cloudflare.com") //for ECH keys
	//dohstr := fmt.Sprintf("https://%s/dns-query?name=%s&type=TYPE65", DoHProvider, servername) //for ECH keys

	dohstr2 := fmt.Sprintf("https://%s/dns-query?name=%s&type=A", DoHProvider, servername) //for A record (Ip addr)
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
