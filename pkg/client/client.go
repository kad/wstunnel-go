package client

import (
	"bufio"
	"context"
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
	"github.com/gorilla/websocket"
	"github.com/kad/wstunnel-go/pkg/protocol"
	"github.com/kad/wstunnel-go/pkg/tunnel"
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
}

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

func (c *Client) connectToWstunnel(p protocol.LocalProtocol, remoteHost string, remotePort uint16) (*websocket.Conn, *http.Response, error) {
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

	dialer := websocket.DefaultDialer
	dialer.HandshakeTimeout = 10 * time.Second

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

	c.runTcpTunnel(ltr)
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
			wsConn, _, err := c.connectToWstunnel(tcpProto, targetHost, targetPort)
			if err != nil {
				slog.Error("Failed to connect to wstunnel for SOCKS5", "err", err)
				return
			}
			defer func() { _ = wsConn.Close() }()

			wsConn.SetPingHandler(func(appData string) error {
				return wsConn.WriteMessage(websocket.PongMessage, []byte(appData))
			})

			tunnel.Pipe(c_net, wsConn)
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
	wsConn, _, err := c.connectToWstunnel(tcpProto, targetHost, uint16(targetPort))
	if err != nil {
		slog.Error("Failed to connect to wstunnel for HTTP Proxy", "err", err)
		return
	}
	defer func() { _ = wsConn.Close() }()

	wsConn.SetPingHandler(func(appData string) error {
		return wsConn.WriteMessage(websocket.PongMessage, []byte(appData))
	})

	tunnel.Pipe(conn, wsConn)
}

func (c *Client) StartReverseTunnel(ltr *protocol.LocalToRemote) {
	maxDelay := 10 * time.Second
	delay := 1 * time.Second

	for {
		wsConn, resp, err := c.connectToWstunnel(ltr.Protocol, ltr.Remote, ltr.Port)
		if err != nil {
			slog.Error("Reverse tunnel: failed to connect to server", "err", err, "retry_in", delay)
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

		cookieStr := resp.Header.Get("Set-Cookie")
		if cookieStr != "" {
			claims := &protocol.JwtTunnelConfig{}
			_, _, err := jwt.NewParser().ParseUnverified(cookieStr, claims)
			if err == nil && claims.Remote != "" {
				targetHost = claims.Remote
				targetPort = claims.Port
				targetProto = claims.Protocol
			}
		}

		var localConn net.Conn
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
			_ = wsConn.Close()
			time.Sleep(1 * time.Second)
			continue
		}

		slog.Info("Reverse tunnel established", "target_host", targetHost, "target_port", targetPort)
		tunnel.Pipe(localConn, wsConn)
		_ = localConn.Close()
		_ = wsConn.Close()
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
			wsConn, _, err := c.connectToWstunnel(ltr.Protocol, ltr.Remote, ltr.Port)
			if err != nil {
				slog.Error("Failed to connect to wstunnel", "err", err)
				return
			}
			defer func() { _ = wsConn.Close() }()

			wsConn.SetPingHandler(func(appData string) error {
				return wsConn.WriteMessage(websocket.PongMessage, []byte(appData))
			})

			tunnel.Pipe(c_net, wsConn)
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

	clients := make(map[string]*websocket.Conn)
	var mu sync.Mutex

	buf := make([]byte, 64*1024)
	for {
		n, srcAddr, err := conn.ReadFromUDP(buf)
		if err != nil {
			slog.Warn("UDP Read error", "err", err)
			continue
		}

		mu.Lock()
		ws, ok := clients[srcAddr.String()]
		if !ok {
			var err error
			ws, _, err = c.connectToWstunnel(ltr.Protocol, ltr.Remote, ltr.Port)
			if err != nil {
				slog.Error("Failed to connect to wstunnel for UDP", "err", err)
				mu.Unlock()
				continue
			}
			clients[srcAddr.String()] = ws

			go func(wsConn *websocket.Conn, dest *net.UDPAddr) {
				defer func() {
					mu.Lock()
					delete(clients, dest.String())
					mu.Unlock()
					_ = wsConn.Close()
				}()
				for {
					messageType, p, err := wsConn.ReadMessage()
					if err != nil {
						return
					}
					if messageType == websocket.BinaryMessage {
						_, _ = conn.WriteToUDP(p, dest)
					}
				}
			}(ws, srcAddr)
		}
		mu.Unlock()

		err = ws.WriteMessage(websocket.BinaryMessage, buf[:n])
		if err != nil {
			slog.Error("Failed to write to WS for UDP", "err", err)
			mu.Lock()
			delete(clients, srcAddr.String())
			mu.Unlock()
			_ = ws.Close()
		}
	}
}

func (c *Client) runStdioTunnel(ltr *protocol.LocalToRemote) {
	wsConn, _, err := c.connectToWstunnel(ltr.Protocol, ltr.Remote, ltr.Port)
	if err != nil {
		slog.Error("Failed to connect to wstunnel for Stdio", "err", err)
		return
	}
	defer func() { _ = wsConn.Close() }()

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		buf := make([]byte, 32*1024)
		for {
			n, err := os.Stdin.Read(buf)
			if n > 0 {
				err = wsConn.WriteMessage(websocket.BinaryMessage, buf[:n])
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
			messageType, p, err := wsConn.ReadMessage()
			if err != nil {
				return
			}
			if messageType == websocket.BinaryMessage || messageType == websocket.TextMessage {
				_, _ = os.Stdout.Write(p)
			}
		}
	}()

	wg.Wait()
}
