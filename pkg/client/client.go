package client

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/kad/wstunnel-go/pkg/protocol"
	"github.com/kad/wstunnel-go/pkg/tunnel"
	"github.com/kad/wstunnel-go/pkg/wst"
	"golang.org/x/net/http2"
)

type Config struct {
	ServerURL                              string            `yaml:"remote_addr"`
	PathPrefix                             string            `yaml:"http_upgrade_path_prefix"`
	Headers                                map[string]string `yaml:"http_headers"`
	MaskFrame                              bool              `yaml:"websocket_mask_frame"`
	PingFrequency                          time.Duration     `yaml:"websocket_ping_frequency"`
	TlsVerifyCert                          bool              `yaml:"tls_verify_certificate"`
	TlsClientCert                          string            `yaml:"tls_certificate"`
	TlsClientKey                           string            `yaml:"tls_private_key"`
	TlsSniOverride                         string            `yaml:"tls_sni_override"`
	TlsSniDisable                          bool              `yaml:"tls_sni_disable"`
	TlsEchEnable                           bool              `yaml:"tls_ech_enable"`
	SocketSoMark                           uint32            `yaml:"socket_so_mark"`
	ConnectionMinIdle                      uint32            `yaml:"connection_min_idle"`
	ConnectionRetryMaxBackoff              time.Duration     `yaml:"connection_retry_max_backoff"`
	ReverseTunnelConnectionRetryMaxBackoff time.Duration     `yaml:"reverse_tunnel_connection_retry_max_backoff"`
	HttpProxy                              string            `yaml:"http_proxy"`
	HttpProxyLogin                         string            `yaml:"http_proxy_login"`
	HttpProxyPassword                      string            `yaml:"http_proxy_password"`
	HttpUpgradeCredentials                 string            `yaml:"http_upgrade_credentials"`
	HttpHeadersFile                        string            `yaml:"http_headers_file"`
	DnsResolver                            []string          `yaml:"dns_resolver"`
	DnsResolverPreferIpv4                  bool              `yaml:"dns_resolver_prefer_ipv4"`
	LocalToRemote                          []string          `yaml:"local_to_remote"`
	RemoteToLocal                          []string          `yaml:"remote_to_local"`
	Transport                              string            `yaml:"transport"`
}

const (
	TransportWebsocket = "websocket"
	TransportHttp2     = "http2"
)

type Client struct {
	Config Config
	pool   *ConnectionPool
}

func NewClient(config Config) *Client {
	c := &Client{Config: config}
	if config.ConnectionMinIdle > 0 {
		c.pool = NewConnectionPool(c, int(config.ConnectionMinIdle))
	}
	return c
}

func (c *Client) generateJWT(requestID string, p protocol.LocalProtocol, remoteHost string, remotePort uint16) (string, error) {
	claims := protocol.JwtTunnelConfig{
		ID:       requestID,
		Protocol: p,
		Remote:   remoteHost,
		Port:     remotePort,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte("champignonfrais"))
}

func (c *Client) loadHttpHeaders() map[string]string {
	headers := make(map[string]string)
	if c.Config.HttpHeadersFile == "" {
		return headers
	}

	file, err := os.Open(c.Config.HttpHeadersFile)
	if err != nil {
		slog.Warn("Failed to open headers file", "path", c.Config.HttpHeadersFile, "err", err)
		return headers
	}
	defer func() { _ = file.Close() }()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.SplitN(line, ":", 2)
		if len(parts) == 2 {
			headers[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
		}
	}
	return headers
}

func (c *Client) connectToWstunnel(p protocol.LocalProtocol, remoteHost string, remotePort uint16) (*wst.Conn, *http.Response, error) {
	requestID := uuid.New().String()
	token, err := c.generateJWT(requestID, p, remoteHost, remotePort)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate JWT: %w", err)
	}

	// Adjust URL to ws scheme to avoid double TLS wrapping if we provide a TLS connection
	u, err := url.Parse(c.Config.ServerURL)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid server url: %w", err)
	}
	if u.Scheme == "wss" || u.Scheme == "https" {
		u.Scheme = "ws"
	}
	u.Path = fmt.Sprintf("/%s/events", c.Config.PathPrefix)

	header := http.Header{}
	header.Set("Sec-WebSocket-Protocol", fmt.Sprintf("v1, %s%s", protocol.JwtHeaderPrefix, token))

	// Add custom headers from CLI
	for k, v := range c.Config.Headers {
		header.Set(k, v)
	}
	// Add custom headers from file (overrides CLI)
	fileHeaders := c.loadHttpHeaders()
	for k, v := range fileHeaders {
		header.Set(k, v)
	}

	// Add basic auth if configured
	if c.Config.HttpUpgradeCredentials != "" {
		header.Set("Authorization", c.Config.HttpUpgradeCredentials)
	}

	dialer := &wst.Dialer{
		HandshakeTimeout: 10 * time.Second,
	}

	// Use pool if available, or dial transport directly
	dialer.NetDialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		if c.pool != nil {
			return c.pool.Get(ctx)
		}
		return c.dialTransport(ctx)
	}

	conn, resp, err := dialer.Dial(u.String(), header)
	if err != nil {
		return nil, resp, fmt.Errorf("failed to dial: %w", err)
	}

	return conn, resp, nil
}

func (c *Client) connectToHttp2(p protocol.LocalProtocol, remoteHost string, remotePort uint16) (io.ReadWriteCloser, *http.Response, error) {
	requestID := uuid.New().String()
	token, err := c.generateJWT(requestID, p, remoteHost, remotePort)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate JWT: %w", err)
	}

	u, err := url.Parse(c.Config.ServerURL)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid server url: %w", err)
	}
	switch u.Scheme {
	case "ws":
		u.Scheme = "http"
	case "wss":
		u.Scheme = "https"
	}
	u.Path = fmt.Sprintf("/%s/events", c.Config.PathPrefix)

	pr, pw := io.Pipe()
	req, err := http.NewRequest("POST", u.String(), pr)
	if err != nil {
		_ = pw.Close()
		return nil, nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Cookie", token)
	req.Header.Set("Content-Type", "application/json")

	// Add custom headers from CLI
	for k, v := range c.Config.Headers {
		req.Header.Set(k, v)
	}
	// Add custom headers from file (overrides CLI)
	fileHeaders := c.loadHttpHeaders()
	for k, v := range fileHeaders {
		req.Header.Set(k, v)
	}

	// Add basic auth if configured
	if c.Config.HttpUpgradeCredentials != "" {
		req.Header.Set("Authorization", c.Config.HttpUpgradeCredentials)
	}

	tr := &http2.Transport{
		AllowHTTP: true,
		DialTLSContext: func(ctx context.Context, network, addr string, cfg *tls.Config) (net.Conn, error) {
			return c.dialTransport(ctx)
		},
	}
	httpClient := &http.Client{Transport: tr}

	resp, err := httpClient.Do(req)
	if err != nil {
		_ = pw.Close()
		return nil, nil, fmt.Errorf("failed to send request: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		_ = pw.Close()
		_ = resp.Body.Close()
		return nil, resp, fmt.Errorf("server rejected request: %s", resp.Status)
	}

	return &tunnelReadWriteCloser{
		ReadCloser: resp.Body,
		Writer:     pw,
	}, resp, nil
}

type tunnelReadWriteCloser struct {
	io.ReadCloser
	io.Writer
}

func (t *tunnelReadWriteCloser) Close() error {
	e1 := t.ReadCloser.Close()
	var e2 error
	if closer, ok := t.Writer.(io.Closer); ok {
		e2 = closer.Close()
	}
	if e1 != nil {
		return e1
	}
	return e2
}

type tunnelStream struct {
	ws  *wst.Conn
	h2  io.ReadWriteCloser
	r   *http.Response
	err error
}

func (ts *tunnelStream) Close() {
	if ts.ws != nil {
		_ = ts.ws.Close()
	}
	if ts.h2 != nil {
		_ = ts.h2.Close()
	}
}

func (c *Client) connectToTransport(p protocol.LocalProtocol, remoteHost string, remotePort uint16) *tunnelStream {
	if c.Config.Transport == TransportHttp2 {
		h2, resp, err := c.connectToHttp2(p, remoteHost, remotePort)
		return &tunnelStream{h2: h2, r: resp, err: err}
	}
	ws, resp, err := c.connectToWstunnel(p, remoteHost, remotePort)
	return &tunnelStream{ws: ws, r: resp, err: err}
}

func (c *Client) StartTunnel(ltr *protocol.LocalToRemote) {
	if ltr.Protocol.Stdio != nil {
		c.runStdioTunnel(ltr)
		return
	}

	if ltr.Protocol.Udp != nil {
		c.runUdpTunnel(ltr)
		return
	}

	if ltr.Protocol.Socks5 != nil {
		c.runSocks5Tunnel(ltr)
		return
	}

	if ltr.Protocol.HttpProxy != nil {
		c.runHttpProxyTunnel(ltr)
		return
	}

	if ltr.Protocol.Unix != nil {
		c.runUnixTunnel(ltr)
		return
	}

	c.runTcpTunnel(ltr)
}

func (c *Client) runUnixTunnel(ltr *protocol.LocalToRemote) {
	_ = os.Remove(ltr.Local)
	listener, err := net.Listen("unix", ltr.Local)
	if err != nil {
		slog.Error("Unix: failed to listen", "path", ltr.Local, "err", err)
		return
	}
	defer func() { _ = listener.Close() }()

	slog.Info("Unix Listener started", "path", ltr.Local, "server", c.Config.ServerURL)

	for {
		conn, err := listener.Accept()
		if err != nil {
			slog.Warn("Unix: failed to accept", "err", err)
			continue
		}

		go func(c_net net.Conn) {
			defer func() { _ = c_net.Close() }()
			ts := c.connectToTransport(ltr.Protocol, ltr.Remote, ltr.Port)
			if ts.err != nil {
				slog.Error("Failed to connect to transport for Unix", "err", ts.err)
				return
			}
			defer ts.Close()

			if ts.ws != nil {
				ts.ws.SetPingHandler(func(appData string) error {
					return ts.ws.WriteMessage(wst.PongMessage, []byte(appData))
				})
				tunnel.Pipe(c_net, ts.ws)
			} else {
				tunnel.PipeBiDir(c_net, ts.h2)
			}
		}(conn)
	}
}

func (c *Client) handleSocks5(conn net.Conn) (string, uint16, error) {
	buf := make([]byte, 256)

	// 1. Version/Methods
	if _, err := io.ReadFull(conn, buf[:2]); err != nil {
		return "", 0, err
	}
	if buf[0] != 0x05 {
		return "", 0, fmt.Errorf("invalid socks version: %d", buf[0])
	}
	nmethods := int(buf[1])
	if _, err := io.ReadFull(conn, buf[:nmethods]); err != nil {
		return "", 0, err
	}
	// Respond: No Authentication Required
	if _, err := conn.Write([]byte{0x05, 0x00}); err != nil {
		return "", 0, err
	}

	// 2. Request
	if _, err := io.ReadFull(conn, buf[:4]); err != nil {
		return "", 0, err
	}
	if buf[0] != 0x05 || buf[1] != 0x01 {
		return "", 0, fmt.Errorf("unsupported socks command: %d", buf[1])
	}

	var host string
	switch buf[3] {
	case 0x01: // IPv4
		if _, err := io.ReadFull(conn, buf[:4]); err != nil {
			return "", 0, err
		}
		host = net.IP(buf[:4]).String()
	case 0x03: // Domain
		if _, err := io.ReadFull(conn, buf[:1]); err != nil {
			return "", 0, err
		}
		sz := int(buf[0])
		if _, err := io.ReadFull(conn, buf[:sz]); err != nil {
			return "", 0, err
		}
		host = string(buf[:sz])
	case 0x04: // IPv6
		if _, err := io.ReadFull(conn, buf[:16]); err != nil {
			return "", 0, err
		}
		host = net.IP(buf[:16]).String()
	default:
		return "", 0, fmt.Errorf("unsupported address type: %d", buf[3])
	}

	if _, err := io.ReadFull(conn, buf[:2]); err != nil {
		return "", 0, err
	}
	port := binary.BigEndian.Uint16(buf[:2])

	// 3. Respond Success
	// [VER, REP, RSV, ATYP, BND.ADDR, BND.PORT]
	resp := []byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}
	if _, err := conn.Write(resp); err != nil {
		return "", 0, err
	}

	return host, port, nil
}

func (c *Client) runSocks5Tunnel(ltr *protocol.LocalToRemote) {
	listener, err := net.Listen("tcp", ltr.Local)
	if err != nil {
		slog.Error("SOCKS5: failed to listen", "local", ltr.Local, "err", err)
		return
	}
	defer func() { _ = listener.Close() }()

	slog.Info("SOCKS5 Listener started", "local", ltr.Local, "server", c.Config.ServerURL)

	for {
		conn, err := listener.Accept()
		if err != nil {
			slog.Warn("SOCKS5: failed to accept", "err", err)
			continue
		}

		go func(c_net net.Conn) {
			defer func() { _ = c_net.Close() }()
			targetHost, targetPort, err := c.handleSocks5(c_net)
			if err != nil {
				slog.Warn("SOCKS5 handshake failed", "err", err)
				return
			}

			// For forward SOCKS5, the server just needs to open a TCP connection to the target
			tcpProto := protocol.LocalProtocol{Tcp: &protocol.TcpProtocol{ProxyProtocol: false}}
			ts := c.connectToTransport(tcpProto, targetHost, targetPort)
			if ts.err != nil {
				slog.Error("Failed to connect to transport for SOCKS5", "err", ts.err)
				return
			}
			defer ts.Close()

			if ts.ws != nil {
				ts.ws.SetPingHandler(func(appData string) error {
					return ts.ws.WriteMessage(wst.PongMessage, []byte(appData))
				})
				tunnel.Pipe(c_net, ts.ws)
			} else {
				tunnel.PipeBiDir(c_net, ts.h2)
			}
		}(conn)
	}
}

func (c *Client) runHttpProxyTunnel(ltr *protocol.LocalToRemote) {
	// Simple HTTP CONNECT Proxy
	listener, err := net.Listen("tcp", ltr.Local)
	if err != nil {
		slog.Error("HTTP Proxy: failed to listen", "local", ltr.Local, "err", err)
		return
	}
	defer func() { _ = listener.Close() }()

	slog.Info("HTTP Proxy Listener started", "local", ltr.Local, "server", c.Config.ServerURL)

	for {
		conn, err := listener.Accept()
		if err != nil {
			slog.Warn("HTTP Proxy: failed to accept", "err", err)
			continue
		}
		go c.handleHttpProxy(conn, ltr)
	}
}

func (c *Client) handleHttpProxy(conn net.Conn, ltr *protocol.LocalToRemote) {
	defer func() { _ = conn.Close() }()

	reader := bufio.NewReader(conn)
	req, err := http.ReadRequest(reader)
	if err != nil {
		slog.Warn("HTTP Proxy: failed to read request", "err", err)
		return
	}

	if req.Method != http.MethodConnect {
		slog.Warn("HTTP Proxy: only CONNECT method is supported currently", "method", req.Method)
		// Send 405 Method Not Allowed
		resp := "HTTP/1.1 405 Method Not Allowed\r\n\r\n"
		_, _ = conn.Write([]byte(resp))
		return
	}

	targetHost, targetPortStr, err := net.SplitHostPort(req.Host)
	if err != nil {
		slog.Warn("HTTP Proxy: invalid target host", "host", req.Host, "err", err)
		return
	}
	targetPort, _ := strconv.ParseUint(targetPortStr, 10, 16)

	// Respond 200 OK
	_, err = conn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
	if err != nil {
		return
	}

	// For HTTP Proxy, we tunnel TCP to target
	tcpProto := protocol.LocalProtocol{Tcp: &protocol.TcpProtocol{ProxyProtocol: false}}
	ts := c.connectToTransport(tcpProto, targetHost, uint16(targetPort))
	if ts.err != nil {
		slog.Error("Failed to connect to transport for HTTP Proxy", "err", ts.err)
		return
	}
	defer ts.Close()

	if ts.ws != nil {
		ts.ws.SetPingHandler(func(appData string) error {
			return ts.ws.WriteMessage(wst.PongMessage, []byte(appData))
		})
		tunnel.Pipe(conn, ts.ws)
	} else {
		tunnel.PipeBiDir(conn, ts.h2)
	}
}

func (c *Client) StartReverseTunnel(ltr *protocol.LocalToRemote) {
	maxDelay := 10 * time.Second
	delay := 1 * time.Second

	for {
		ts := c.connectToTransport(ltr.Protocol, ltr.Remote, ltr.Port)
		if ts.err != nil {
			slog.Error("Reverse tunnel: failed to connect to transport", "err", ts.err, "retry_in", delay)
			time.Sleep(delay)
			delay *= 2
			if delay > maxDelay {
				delay = maxDelay
			}
			continue
		}
		delay = 1 * time.Second

		// Check for target in cookies (for dynamic reverse tunnels)
		targetHost := ltr.Remote
		targetPort := ltr.Port
		targetProto := ltr.Protocol

		if ts.r.Header.Get("Set-Cookie") != "" {
			cookieStr := ts.r.Header.Get("Set-Cookie")
			claims := &protocol.JwtTunnelConfig{}
			_, _, err := jwt.NewParser().ParseUnverified(cookieStr, claims)
			if err == nil && claims.Remote != "" {
				targetHost = claims.Remote
				targetPort = claims.Port
				targetProto = claims.Protocol
			}
		}

		var localConn net.Conn
		var err error
		if targetProto.Unix != nil || targetProto.ReverseUnix != nil {
			path := ""
			if targetProto.Unix != nil {
				path = targetProto.Unix.Path
			} else {
				path = targetProto.ReverseUnix.Path
			}
			localConn, err = net.Dial("unix", path)
		} else {
			localConn, err = net.Dial("tcp", net.JoinHostPort(targetHost, fmt.Sprintf("%d", targetPort)))
		}

		if err != nil {
			slog.Error("Reverse tunnel: failed to connect to local destination", "host", targetHost, "port", targetPort, "err", err)
			ts.Close()
			time.Sleep(1 * time.Second)
			continue
		}

		slog.Info("Reverse tunnel established", "target_host", targetHost, "target_port", targetPort)
		if ts.ws != nil {
			tunnel.Pipe(localConn, ts.ws)
		} else {
			tunnel.PipeBiDir(localConn, ts.h2)
		}
		_ = localConn.Close()
		ts.Close()
		slog.Info("Reverse tunnel closed")
	}
}

func (c *Client) runTcpTunnel(ltr *protocol.LocalToRemote) {
	listener, err := net.Listen("tcp", ltr.Local)
	if err != nil {
		slog.Error("Failed to listen", "local", ltr.Local, "err", err)
		return
	}
	defer func() { _ = listener.Close() }()

	slog.Info("TCP Listener started", "local", ltr.Local, "remote", ltr.Remote, "port", ltr.Port)

	for {
		conn, err := listener.Accept()
		if err != nil {
			slog.Warn("Failed to accept", "err", err)
			continue
		}

		go func(c_net net.Conn) {
			defer func() { _ = c_net.Close() }()
			ts := c.connectToTransport(ltr.Protocol, ltr.Remote, ltr.Port)
			if ts.err != nil {
				slog.Error("Failed to connect to transport", "err", ts.err)
				return
			}
			defer ts.Close()

			if ts.ws != nil {
				ts.ws.SetPingHandler(func(appData string) error {
					return ts.ws.WriteMessage(wst.PongMessage, []byte(appData))
				})
				tunnel.Pipe(c_net, ts.ws)
			} else {
				tunnel.PipeBiDir(c_net, ts.h2)
			}
		}(conn)
	}
}

func (c *Client) runUdpTunnel(ltr *protocol.LocalToRemote) {
	addr, err := net.ResolveUDPAddr("udp", ltr.Local)
	if err != nil {
		slog.Error("Failed to resolve UDP addr", "local", ltr.Local, "err", err)
		return
	}

	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		slog.Error("Failed to listen on UDP", "local", ltr.Local, "err", err)
		return
	}
	defer func() { _ = conn.Close() }()

	slog.Info("UDP Listener started", "local", ltr.Local, "remote", ltr.Remote, "port", ltr.Port)

	clients := make(map[string]*tunnelStream)
	var mu sync.Mutex

	buf := make([]byte, 64*1024)
	for {
		n, srcAddr, err := conn.ReadFromUDP(buf)
		if err != nil {
			slog.Warn("UDP Read error", "err", err)
			continue
		}

		mu.Lock()
		ts, ok := clients[srcAddr.String()]
		if !ok {
			ts = c.connectToTransport(ltr.Protocol, ltr.Remote, ltr.Port)
			if ts.err != nil {
				slog.Error("Failed to connect to transport for UDP", "err", ts.err)
				mu.Unlock()
				continue
			}
			clients[srcAddr.String()] = ts

			go func(ts *tunnelStream, dest *net.UDPAddr) {
				defer func() {
					mu.Lock()
					delete(clients, dest.String())
					mu.Unlock()
					ts.Close()
				}()

				if ts.ws != nil {
					for {
						messageType, p, err := ts.ws.ReadMessage()
						if err != nil {
							return
						}
						if messageType == wst.BinaryMessage {
							_, _ = conn.WriteToUDP(p, dest)
						}
					}
				} else {
					buf := make([]byte, 64*1024)
					for {
						n, err := ts.h2.Read(buf)
						if n > 0 {
							_, _ = conn.WriteToUDP(buf[:n], dest)
						}
						if err != nil {
							return
						}
					}
				}
			}(ts, srcAddr)
		}
		mu.Unlock()

		if ts.ws != nil {
			err = ts.ws.WriteMessage(wst.BinaryMessage, buf[:n])
		} else {
			_, err = ts.h2.Write(buf[:n])
		}

		if err != nil {
			slog.Error("Failed to write to transport for UDP", "err", err)
			mu.Lock()
			delete(clients, srcAddr.String())
			mu.Unlock()
			ts.Close()
		}
	}
}

func (c *Client) runStdioTunnel(ltr *protocol.LocalToRemote) {
	ts := c.connectToTransport(ltr.Protocol, ltr.Remote, ltr.Port)
	if ts.err != nil {
		slog.Error("Failed to connect to transport for Stdio", "err", ts.err)
		return
	}
	defer ts.Close()

	if ts.ws != nil {
		var wg sync.WaitGroup
		wg.Add(2)

		go func() {
			defer wg.Done()
			buf := make([]byte, 32*1024)
			for {
				n, err := os.Stdin.Read(buf)
				if n > 0 {
					err = ts.ws.WriteMessage(wst.BinaryMessage, buf[:n])
					if err != nil {
						return
					}
				}
				if err != nil {
					return
				}
			}
		}()

		go func() {
			defer wg.Done()
			for {
				messageType, p, err := ts.ws.ReadMessage()
				if err != nil {
					return
				}
				if messageType == wst.BinaryMessage || messageType == wst.TextMessage {
					_, _ = os.Stdout.Write(p)
				}
			}
		}()

		wg.Wait()
	} else {
		// HTTP/2 is already a ReadWriteCloser
		tunnel.PipeBiDir(os.Stdin, ts.h2)
	}
}
