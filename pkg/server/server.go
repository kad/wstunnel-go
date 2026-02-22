package server

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"syscall"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/kad/wstunnel-go/internal/socket"
	"github.com/kad/wstunnel-go/pkg/protocol"
	"github.com/kad/wstunnel-go/pkg/tunnel"
	"github.com/kad/wstunnel-go/pkg/wst"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
)

type Config struct {
	ListenAddr                     string        `yaml:"remote_addr"`
	PathPrefix                     string        `yaml:"restrict_http_upgrade_path_prefix"`
	SocketSoMark                   uint32        `yaml:"socket_so_mark"`
	WebsocketPingFrequency         time.Duration `yaml:"websocket_ping_frequency"`
	WebsocketMaskFrame             bool          `yaml:"websocket_mask_frame"`
	DnsResolver                    []string      `yaml:"dns_resolver"`
	DnsResolverPreferIpv4          bool          `yaml:"dns_resolver_prefer_ipv4"`
	RestrictTo                     []string      `yaml:"restrict_to"`
	RestrictHttpUpgradePathPrefix  []string      `yaml:"restrict_http_upgrade_path_prefix_list"` // Renamed list to avoid clash? No, Rust uses same name but different structure.
	RestrictConfig                 string        `yaml:"restrict_config"`
	TlsCertificate                 string        `yaml:"tls_certificate"`
	TlsPrivateKey                  string        `yaml:"tls_private_key"`
	TlsClientCaCerts               string        `yaml:"tls_client_ca_certs"`
	HttpProxy                      string        `yaml:"http_proxy"`
	HttpProxyLogin                 string        `yaml:"http_proxy_login"`
	HttpProxyPassword              string        `yaml:"http_proxy_password"`
	RemoteToLocalServerIdleTimeout time.Duration `yaml:"remote_to_local_server_idle_timeout"`
}

type Server struct {
	Config Config
	mux    *http.ServeMux
	rvMgr  *ReverseTunnelManager
	rules  *RestrictionsRules
}

func NewServer(config Config) *Server {
	var rules *RestrictionsRules
	if config.RestrictConfig != "" {
		var err error
		rules, err = LoadRestrictions(config.RestrictConfig)
		if err != nil {
			slog.Error("Failed to load restrictions", "path", config.RestrictConfig, "err", err)
		}
	}

	s := &Server{
		Config: config,
		mux:    http.NewServeMux(),
		rvMgr:  NewReverseTunnelManager(config.SocketSoMark),
		rules:  rules,
	}
	s.mux.HandleFunc("/", s.handleRequest)
	return s
}

func (s *Server) Start() error {
	slog.Info("Server starting", "listen_addr", s.Config.ListenAddr)

	bindAddr := s.Config.ListenAddr
	if strings.Contains(bindAddr, "://") {
		u, err := url.Parse(bindAddr)
		if err == nil {
			bindAddr = u.Host
		}
	}

	var lc net.ListenConfig
	if s.Config.SocketSoMark != 0 {
		lc.Control = func(network, address string, c syscall.RawConn) error {
			return c.Control(func(fd uintptr) {
				_ = socket.SetSoMark(fd, s.Config.SocketSoMark)
			})
		}
	}

	ln, err := lc.Listen(context.Background(), "tcp", bindAddr)
	if err != nil {
		return err
	}

	h2s := &http2.Server{}
	handler := h2c.NewHandler(s.mux, h2s)
	srv := &http.Server{
		Addr:    bindAddr,
		Handler: handler,
	}

	if s.Config.TlsCertificate != "" && s.Config.TlsPrivateKey != "" {
		tlsConfig := &tls.Config{
			MinVersion: tls.VersionTLS12,
		}

		if s.Config.TlsClientCaCerts != "" {
			caCert, err := os.ReadFile(s.Config.TlsClientCaCerts)
			if err != nil {
				return fmt.Errorf("failed to read client CA certs: %w", err)
			}
			caCertPool := x509.NewCertPool()
			caCertPool.AppendCertsFromPEM(caCert)
			tlsConfig.ClientCAs = caCertPool
			tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
		}

		srv.TLSConfig = tlsConfig
		return srv.ServeTLS(ln, s.Config.TlsCertificate, s.Config.TlsPrivateKey)
	}

	return srv.Serve(ln)
}

func (s *Server) handleRequest(w http.ResponseWriter, r *http.Request) {
	// Check path prefix if configured
	if s.Config.PathPrefix != "" {
		expectedPrefix := "/" + s.Config.PathPrefix
		if !strings.HasPrefix(r.URL.Path, expectedPrefix) {
			http.Error(w, "Not found", http.StatusNotFound)
			return
		}
	}

	// Extract Sec-WebSocket-Protocol
	wsProtoHeader := r.Header.Get("Sec-WebSocket-Protocol")
	parts := strings.Split(wsProtoHeader, ",")
	var tokenStr string

	for _, part := range parts {
		part = strings.TrimSpace(part)
		if strings.HasPrefix(part, protocol.JwtHeaderPrefix) {
			tokenStr = strings.TrimPrefix(part, protocol.JwtHeaderPrefix)
			break
		}
	}

	if tokenStr == "" {
		// Try Cookie header for HTTP/2
		tokenStr = r.Header.Get("Cookie")
	}

	if tokenStr == "" {
		http.Error(w, "Missing authorization token", http.StatusUnauthorized)
		return
	}

	// Decode JWT
	claims := &protocol.JwtTunnelConfig{}
	_, _, err := jwt.NewParser().ParseUnverified(tokenStr, claims)
	if err != nil {
		slog.Warn("Invalid token", "err", err)
		http.Error(w, "Invalid token", http.StatusUnauthorized)
		return
	}

	// Validate restrictions
	if s.rules != nil {
		auth := r.Header.Get("Authorization")
		if !s.rules.Validate(claims, r.URL.Path, auth) {
			slog.Warn("Tunnel rejected by restrictions", "tunnel_id", claims.ID)
			http.Error(w, "Forbidden by restrictions", http.StatusForbidden)
			return
		}
	}

	// If HTTP/2 and not a websocket upgrade, handle as HTTP/2 tunnel
	isWebsocket := strings.ToLower(r.Header.Get("Upgrade")) == "websocket"
	if r.ProtoAtLeast(2, 0) && !isWebsocket {
		s.handleHttp2Connection(w, r, claims)
		return
	}

	// Upgrade to WebSocket
	upgrader := wst.Upgrader{
		CheckOrigin: func(r *http.Request) bool { return true },
	}

	// Selection of subprotocol (simplified)
	if strings.Contains(r.Header.Get("Sec-WebSocket-Protocol"), "v1") {
		upgrader.Subprotocols = []string{"v1"}
	}

	wsConn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		slog.Error("Upgrade failed", "err", err)
		return
	}

	slog.Info("Accepted tunnel", "id", claims.ID, "remote", claims.Remote, "port", claims.Port, "subprotocol", wsConn.Subprotocol())
	go s.handleConnection(wsConn, claims)
}

func (s *Server) handleConnection(wsConn *wst.Conn, claims *protocol.JwtTunnelConfig) {
	defer func() { _ = wsConn.Close() }()

	// Handle PING from client
	wsConn.SetPingHandler(func(appData string) error {
		return wsConn.WriteMessage(wst.PongMessage, []byte(appData))
	})

	// Forward Tunnel
	if claims.Protocol.Tcp != nil || claims.Protocol.Udp != nil || claims.Protocol.Socks5 != nil || claims.Protocol.HttpProxy != nil || claims.Protocol.Unix != nil {
		var targetAddr string
		network := "tcp"

		if claims.Protocol.Unix != nil {
			targetAddr = claims.Protocol.Unix.Path
			network = "unix"
		} else {
			targetAddr = net.JoinHostPort(claims.Remote, fmt.Sprintf("%d", claims.Port))
			if claims.Protocol.Udp != nil {
				network = "udp"
			}
		}

		conn, err := net.DialTimeout(network, targetAddr, 10*time.Second)
		if err != nil {
			slog.Error("Failed to connect to target", "network", network, "target", targetAddr, "err", err)
			return
		}
		defer func() { _ = conn.Close() }()

		tunnel.Pipe(conn, wsConn)
		return
	}

	// Reverse Tunnel
	if claims.Protocol.ReverseTcp != nil || claims.Protocol.ReverseUdp != nil || claims.Protocol.ReverseSocks5 != nil || claims.Protocol.ReverseHttpProxy != nil {
		s.rvMgr.HandleClient(wsConn, claims)
		return
	}

	slog.Warn("Unsupported protocol", "proto", claims.Protocol)
}

func (s *Server) handleHttp2Connection(w http.ResponseWriter, r *http.Request, claims *protocol.JwtTunnelConfig) {
	w.WriteHeader(http.StatusOK)
	if f, ok := w.(http.Flusher); ok {
		f.Flush()
	}

	slog.Info("Accepted HTTP/2 tunnel", "id", claims.ID, "remote", claims.Remote, "port", claims.Port)
	rwc := &http2ReadWriteCloser{r.Body, w}

	// Forward Tunnel
	if claims.Protocol.Tcp != nil || claims.Protocol.Udp != nil || claims.Protocol.Socks5 != nil || claims.Protocol.HttpProxy != nil || claims.Protocol.Unix != nil {
		var targetAddr string
		network := "tcp"

		if claims.Protocol.Unix != nil {
			targetAddr = claims.Protocol.Unix.Path
			network = "unix"
		} else {
			targetAddr = net.JoinHostPort(claims.Remote, fmt.Sprintf("%d", claims.Port))
			if claims.Protocol.Udp != nil {
				network = "udp"
			}
		}

		conn, err := net.DialTimeout(network, targetAddr, 10*time.Second)
		if err != nil {
			slog.Error("Failed to connect to target", "network", network, "target", targetAddr, "err", err)
			_ = rwc.Close()
			return
		}
		defer func() { _ = conn.Close() }()

		tunnel.PipeBiDir(conn, rwc)
		return
	}

	// Reverse Tunnel
	if claims.Protocol.ReverseTcp != nil || claims.Protocol.ReverseUdp != nil || claims.Protocol.ReverseSocks5 != nil || claims.Protocol.ReverseHttpProxy != nil {
		s.rvMgr.HandleClientH2(rwc, claims)
		return
	}

	slog.Warn("Unsupported protocol for HTTP/2", "proto", claims.Protocol)
	_ = rwc.Close()
}

type http2ReadWriteCloser struct {
	io.ReadCloser
	io.Writer
}

func (h *http2ReadWriteCloser) Close() error {
	return h.ReadCloser.Close()
}
