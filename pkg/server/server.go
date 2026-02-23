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
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/gorilla/websocket"
	"github.com/kad/wstunnel-go/internal/socket"
	"github.com/kad/wstunnel-go/pkg/protocol"
	"github.com/kad/wstunnel-go/pkg/tunnel"
	"github.com/kad/wstunnel-go/pkg/wst"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
)

type Config struct {
	ListenAddr                     string        `yaml:"listen_addr"`
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
	WebsocketProtocol              string        `yaml:"mode"` // "rust" or "ws"
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

	// If no rules loaded from file, but we have CLI/Config restrictions, create them
	if rules == nil && (len(config.RestrictTo) > 0 || len(config.RestrictHttpUpgradePathPrefix) > 0) {
		rules = &RestrictionsRules{}
		rc := RestrictionConfig{
			Name: "Default Restrictions",
		}
		if len(config.RestrictHttpUpgradePathPrefix) > 0 {
			for _, p := range config.RestrictHttpUpgradePathPrefix {
				re, err := regexp.Compile("^/" + strings.TrimPrefix(p, "/"))
				if err == nil {
					rc.Match = append(rc.Match, MatchConfig{PathPrefix: re})
				}
			}
		} else {
			rc.Match = append(rc.Match, MatchConfig{Any: true})
		}

		if len(config.RestrictTo) > 0 {
			for _, r := range config.RestrictTo {
				host, portStr, err := net.SplitHostPort(r)
				if err == nil {
					port, _ := strconv.ParseUint(portStr, 10, 16)
					re, _ := regexp.Compile("^" + regexp.QuoteMeta(host) + "$")
					rc.Allow = append(rc.Allow, AllowConfig{
						Tunnel: &AllowTunnelConfig{
							Host: &Regexp{re},
							Port: []PortRange{{Min: uint16(port), Max: uint16(port)}},
						},
					})
				}
			}
		} else {
			rc.Allow = append(rc.Allow, AllowConfig{
				Tunnel:        &AllowTunnelConfig{},
				ReverseTunnel: &AllowReverseTunnelConfig{},
			})
		}
		rules.Restrictions = append(rules.Restrictions, rc)
	}

	s := &Server{
		Config: config,
		mux:    http.NewServeMux(),
		rvMgr:  NewReverseTunnelManager(config.SocketSoMark),
		rules:  rules,
	}
	s.mux.HandleFunc("/", s.ServeHTTP)
	return s
}

func (s *Server) SetRules(rules *RestrictionsRules) {
	s.rules = rules
}

func (s *Server) GetRules() *RestrictionsRules {
	return s.rules
}

func (s *Server) Start() error {
	slog.Info("Server starting", "listen_addr", s.Config.ListenAddr)

	bindAddr := s.Config.ListenAddr
	if strings.Contains(bindAddr, "://") {
		u, err := url.Parse(bindAddr)
		if err == nil {
			host := u.Hostname()
			port := u.Port()
			if port == "" {
				if u.Scheme == "wss" || u.Scheme == "https" {
					port = "443"
				} else {
					port = "80"
				}
			}
			bindAddr = net.JoinHostPort(host, port)
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

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
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
		commonName := ""
		if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
			commonName = r.TLS.PeerCertificates[0].Subject.CommonName
		}
		if !s.rules.Validate(claims, r.URL.Path, auth, commonName) {
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

	if s.Config.WebsocketProtocol == "ws" {
		upgrader := websocket.Upgrader{
			CheckOrigin: func(r *http.Request) bool { return true },
		}
		for _, subprotocol := range strings.Split(r.Header.Get("Sec-WebSocket-Protocol"), ",") {
			if strings.TrimSpace(subprotocol) == "v1" {
				upgrader.Subprotocols = []string{"v1"}
				break
			}
		}

		wsConn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			slog.Error("Gorilla upgrade failed", "err", err)
			return
		}

		slog.Info("Accepted gorilla tunnel", "id", claims.ID, "remote", claims.Remote, "port", claims.Port, "subprotocol", wsConn.Subprotocol())
		go s.handleGorillaConnection(wsConn, claims)
		return
	}

	// Upgrade to WebSocket
	upgrader := wst.Upgrader{
		CheckOrigin: func(r *http.Request) bool { return true },
	}

	// Selection of subprotocol (simplified)
	for _, subprotocol := range strings.Split(r.Header.Get("Sec-WebSocket-Protocol"), ",") {
		if strings.TrimSpace(subprotocol) == "v1" {
			upgrader.Subprotocols = []string{"v1"}
			break
		}
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

func (s *Server) handleGorillaConnection(wsConn *websocket.Conn, claims *protocol.JwtTunnelConfig) {
	defer func() { _ = wsConn.Close() }()

	wsConn.SetPingHandler(func(appData string) error {
		return wsConn.WriteMessage(websocket.PongMessage, []byte(appData))
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
			slog.Error("Failed to connect to target (gorilla)", "network", network, "target", targetAddr, "err", err)
			return
		}
		defer func() { _ = conn.Close() }()

		tunnel.PipeGorilla(conn, wsConn)
		return
	}

	// Reverse Tunnel
	if claims.Protocol.ReverseTcp != nil || claims.Protocol.ReverseUdp != nil || claims.Protocol.ReverseSocks5 != nil || claims.Protocol.ReverseHttpProxy != nil {
		s.rvMgr.HandleGorillaClient(wsConn, claims)
		return
	}

	slog.Warn("Unsupported protocol (gorilla)", "proto", claims.Protocol)
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
