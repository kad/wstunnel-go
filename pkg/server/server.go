package server

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/gorilla/websocket"
	"github.com/kad/wstunnel-go/internal/socket"
	"github.com/kad/wstunnel-go/pkg/protocol"
	"github.com/kad/wstunnel-go/pkg/tun"
	"github.com/kad/wstunnel-go/pkg/tunnel"
	"github.com/kad/wstunnel-go/pkg/wst"
)

var insecureWSModeJWTWarning sync.Once

type Config struct {
	ListenAddr                     string        `yaml:"listen_addr"`
	PathPrefix                     string        `yaml:"http_upgrade_path_prefix"`
	JWTSecret                      string        `yaml:"jwt_secret"`
	InsecureNoJWTValidation        bool          `yaml:"insecure_no_jwt_validation"`
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
	// EnableTun admits packet-level tun sessions (a Go-only extension). It is
	// required even when restrictions allow every protocol.
	EnableTun     bool          `yaml:"enable_tun"`
	TunUdpTimeout time.Duration `yaml:"tun_udp_timeout"`
	// TunMaxFlows bounds the outbound flows of all tun sessions together;
	// TunMaxSessions bounds concurrent tun sessions. Zero selects the defaults.
	TunMaxFlows    int `yaml:"tun_max_flows"`
	TunMaxSessions int `yaml:"tun_max_sessions"`
	// TunAllow, when non-empty, limits the destinations of tun flows to these
	// networks (CIDR, or a bare address for a single host), in addition to any
	// restriction rule. It does not affect other tunnel types and does not lift
	// the built-in deny list.
	TunAllow []string `yaml:"tun_allow"`
}

// Server-wide tun limits applied when the Config leaves them zero.
const (
	DefaultTunMaxFlows    = tun.DefaultMaxFlows
	DefaultTunMaxSessions = 256
)

func (c *Config) UnmarshalYAML(unmarshal func(any) error) error {
	type rawConfig Config
	aux := struct {
		rawConfig        `yaml:",inline"`
		LegacyPathPrefix string `yaml:"restrict_http_upgrade_path_prefix"`
	}{}

	if err := unmarshal(&aux); err != nil {
		return err
	}

	*c = Config(aux.rawConfig)
	if c.PathPrefix == "" {
		c.PathPrefix = aux.LegacyPathPrefix
	}

	return nil
}

type Server struct {
	Config   Config
	mux      *http.ServeMux
	rvMgr    *ReverseTunnelManager
	rules    *RestrictionsRules
	wtServer *WebTransportServer

	tunFlowSlots    chan struct{} // shared by all tun sessions
	tunSessionSlots chan struct{}

	// ctx ends when the server is closed; tun sessions run under it.
	ctx       context.Context
	cancel    context.CancelFunc
	closeOnce sync.Once
	closeErr  error

	// tunAllow is the parsed Config.TunAllow. tunAllowSet distinguishes "no
	// limit" from a configured list that failed to parse, which must deny every
	// tun flow rather than silently allow them.
	tunAllow    []netip.Prefix
	tunAllowSet bool
}

// ValidateConfig reports configuration that would make NewServer start with
// weaker protection than the operator asked for: a restriction file that cannot
// be loaded, a malformed tun_allow or restrict_to entry. Command-line and
// embedding callers use it to refuse to start instead of serving.
func ValidateConfig(config Config) error {
	if config.RestrictConfig != "" {
		if _, err := LoadRestrictions(config.RestrictConfig); err != nil {
			return fmt.Errorf("restrict_config %q: %w", config.RestrictConfig, err)
		}
	}
	for _, r := range config.RestrictTo {
		_, port, err := net.SplitHostPort(r)
		if err != nil {
			return fmt.Errorf("restrict_to %q: want host:port: %w", r, err)
		}
		// NewServer turns the port into a number; anything that is not one
		// would silently become a rule for port 0.
		if _, err := strconv.ParseUint(port, 10, 16); err != nil {
			return fmt.Errorf("restrict_to %q: the port must be a number from 0 to 65535: %w", r, err)
		}
	}
	// NewServer treats zero as "use the default"; a negative value is a typo,
	// and must not quietly become the (much larger) default capacity.
	if config.TunMaxFlows < 0 {
		return fmt.Errorf("tun_max_flows %d is negative", config.TunMaxFlows)
	}
	if config.TunMaxSessions < 0 {
		return fmt.Errorf("tun_max_sessions %d is negative", config.TunMaxSessions)
	}
	if config.TunUdpTimeout < 0 {
		return fmt.Errorf("tun_udp_timeout %v is negative: every UDP flow would expire at once", config.TunUdpTimeout)
	}
	if _, err := ParseTunAllow(config.TunAllow); err != nil {
		return err
	}
	return nil
}

func NewServer(config Config) *Server {
	if config.TunMaxFlows <= 0 {
		config.TunMaxFlows = DefaultTunMaxFlows
	}
	if config.TunMaxSessions <= 0 {
		config.TunMaxSessions = DefaultTunMaxSessions
	}
	if config.WebsocketProtocol == "ws" && config.JWTSecret == "" {
		insecureWSModeJWTWarning.Do(func() {
			slog.Warn("Server running in ws mode without jwt_secret; tunnel JWTs are parsed but not cryptographically verified")
		})
	}

	var rules *RestrictionsRules
	if config.RestrictConfig != "" {
		var err error
		rules, err = LoadRestrictions(config.RestrictConfig)
		if err != nil {
			// Never fall back to "no restrictions": a server built in code
			// from a restriction file that cannot be read refuses every
			// tunnel. ValidateConfig lets callers refuse to start instead.
			slog.Error("Failed to load restrictions; refusing every tunnel", "path", config.RestrictConfig, "err", err)
			rules = &RestrictionsRules{Restrictions: []RestrictionConfig{{Name: "restrict_config failed to load (denying all)"}}}
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
			// Admit tun sessions; their flows are then checked against the
			// host/port entries above.
			rc.Allow = append(rc.Allow, AllowConfig{
				Tunnel: &AllowTunnelConfig{Protocol: []string{"Tun"}},
			})
		} else {
			rc.Allow = append(rc.Allow, AllowConfig{
				Tunnel:        &AllowTunnelConfig{},
				ReverseTunnel: &AllowReverseTunnelConfig{},
			})
		}
		rules.Restrictions = append(rules.Restrictions, rc)
	}

	ctx, cancel := context.WithCancel(context.Background())
	tunAllow, tunAllowErr := ParseTunAllow(config.TunAllow)
	if tunAllowErr != nil {
		slog.Error("Invalid tun_allow; every tun flow will be refused", "err", tunAllowErr)
	}
	s := &Server{
		Config: config,
		mux:    http.NewServeMux(),
		rvMgr:  NewReverseTunnelManager(config.SocketSoMark, config.RemoteToLocalServerIdleTimeout).withPingInterval(config.WebsocketPingFrequency).withCookieSigner(cookieSigner(config.JWTSecret)),
		rules:  rules,

		tunFlowSlots:    make(chan struct{}, config.TunMaxFlows),
		tunSessionSlots: make(chan struct{}, config.TunMaxSessions),

		ctx:    ctx,
		cancel: cancel,

		tunAllow:    tunAllow,
		tunAllowSet: len(config.TunAllow) > 0,
	}
	s.wtServer = NewWebTransportServer(s)
	s.mux.HandleFunc("/", s.ServeHTTP)
	return s
}

// Close ends the server's long-lived work: every tun session is closed, the
// reverse-tunnel listeners are released, and a WebTransport listener started by
// Start is shut down. A closed server refuses new tun sessions.
//
// Close does not stop the HTTP listener that Start opened (end Start by closing
// that listener's process or by embedding the server behind another HTTP server,
// as the Caddy module does), and forward tunnels that are already piping data
// are left to finish. Close is safe to call more than once.
func (s *Server) Close() error {
	s.closeOnce.Do(func() {
		s.cancel()
		s.rvMgr.Close()
		s.closeErr = s.wtServer.Close()
	})
	return s.closeErr
}

// parseJWTClaims verifies the token and returns its claims. It refuses a claim
// that names more than one protocol: the restrictions are checked against one of
// them and the tunnel is served as another, so such a claim could be authorized
// as a protocol it does not use.
func (s *Server) parseJWTClaims(tokenStr string) (*protocol.JwtTunnelConfig, error) {
	claims, err := s.verifyJWTClaims(tokenStr)
	if err != nil {
		return nil, err
	}
	if n := claims.Protocol.Variants(); n > 1 {
		return nil, fmt.Errorf("the tunnel claim names %d protocols, want one", n)
	}
	return claims, nil
}

func (s *Server) verifyJWTClaims(tokenStr string) (*protocol.JwtTunnelConfig, error) {
	parseUnverified := func() (*protocol.JwtTunnelConfig, error) {
		claims := &protocol.JwtTunnelConfig{}
		token, _, err := jwt.NewParser().ParseUnverified(tokenStr, claims)
		if err != nil {
			return nil, err
		}
		if token.Method != jwt.SigningMethodHS256 {
			return nil, fmt.Errorf("unexpected signing method: %s", jwtSigningMethodName(token))
		}
		return claims, nil
	}

	if s.Config.WebsocketProtocol != "ws" {
		return parseUnverified()
	}

	claims := &protocol.JwtTunnelConfig{}

	if s.Config.JWTSecret != "" {
		token, err := jwt.ParseWithClaims(tokenStr, claims, func(token *jwt.Token) (any, error) {
			if token.Method != jwt.SigningMethodHS256 {
				return nil, fmt.Errorf("unexpected signing method: %s", jwtSigningMethodName(token))
			}
			return []byte(s.Config.JWTSecret), nil
		})
		if err == nil && token != nil && token.Valid {
			return claims, nil
		}
		if !s.Config.InsecureNoJWTValidation {
			if err != nil {
				return nil, err
			}
			return nil, fmt.Errorf("invalid JWT token")
		}
	}

	return parseUnverified()
}

func jwtSigningMethodName(token *jwt.Token) string {
	if token == nil || token.Method == nil {
		return "<nil>"
	}
	return token.Method.Alg()
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
	defer func() { _ = ln.Close() }()
	// The bound address, which differs from the configured one for port 0.
	slog.Info("Server listening", "addr", ln.Addr().String())
	webTransportStarted := false
	defer func() {
		if webTransportStarted {
			_ = s.wtServer.Close()
		}
	}()

	// Enable HTTP/1.1, HTTP/2 over TLS, and cleartext HTTP/2 (h2c) so clients
	// using prior-knowledge h2c reach the tunnel handler directly.
	protocols := new(http.Protocols)
	protocols.SetHTTP1(true)
	protocols.SetHTTP2(true)
	protocols.SetUnencryptedHTTP2(true)

	srv := &http.Server{
		Addr:      bindAddr,
		Handler:   s.mux,
		Protocols: protocols,
	}

	if s.Config.TlsCertificate != "" && s.Config.TlsPrivateKey != "" {
		certs, err := newCertReloader(s.Config.TlsCertificate, s.Config.TlsPrivateKey, certReloadInterval)
		if err != nil {
			return fmt.Errorf("load TLS certificate: %w", err)
		}
		tlsConfig := &tls.Config{
			MinVersion:     tls.VersionTLS12,
			GetCertificate: certs.GetCertificate,
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
		if strings.HasPrefix(s.Config.ListenAddr, "wt://") || strings.HasPrefix(s.Config.ListenAddr, "wts://") {
			if err := s.wtServer.Start(wtBindAddr(bindAddr, ln.Addr()), tlsConfig.Clone()); err != nil {
				return fmt.Errorf("start WebTransport server: %w", err)
			}
			webTransportStarted = true
		}
		// The certificate comes from tlsConfig.GetCertificate, so it can be reloaded.
		return srv.ServeTLS(ln, "", "")
	}

	if strings.HasPrefix(s.Config.ListenAddr, "wt://") || strings.HasPrefix(s.Config.ListenAddr, "wts://") {
		if err := s.wtServer.Start(wtBindAddr(bindAddr, ln.Addr()), nil); err != nil {
			return fmt.Errorf("start WebTransport server: %w", err)
		}
		webTransportStarted = true
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
		slog.Warn("Missing authorization token", "path", r.URL.Path, "client", r.RemoteAddr)
		http.Error(w, "Missing authorization token", http.StatusUnauthorized)
		return
	}

	// Decode JWT
	claims, err := s.parseJWTClaims(tokenStr)
	if err != nil {
		slog.Warn("Invalid token", "err", err, "path", r.URL.Path, "client", r.RemoteAddr)
		http.Error(w, "Invalid token", http.StatusUnauthorized)
		return
	}
	normalizeTunClaims(claims)

	// Validate restrictions
	var rule *RestrictionConfig
	if s.rules != nil {
		auth := r.Header.Get("Authorization")
		commonName := ""
		if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
			commonName = r.TLS.PeerCertificates[0].Subject.CommonName
		}
		var ok bool
		rule, ok = s.rules.ValidateMatch(claims, r.URL.Path, auth, commonName)
		if !ok {
			slog.Warn("Tunnel rejected by restrictions", "tunnel_id", claims.ID, "proto", getProtoName(claims.Protocol), "remote", claims.Remote, "port", claims.Port, "path", r.URL.Path, "client", r.RemoteAddr)
			http.Error(w, "Forbidden by restrictions", http.StatusForbidden)
			return
		}
	}
	if err := s.admitTun(claims); err != nil {
		slog.Warn("Tunnel rejected", "tunnel_id", claims.ID, "err", err)
		http.Error(w, err.Error(), tunAdmitStatus(err))
		return
	}

	// If HTTP/2 and not a websocket upgrade, handle as HTTP/2 tunnel
	isWebsocket := strings.ToLower(r.Header.Get("Upgrade")) == "websocket"
	if r.ProtoAtLeast(2, 0) && !isWebsocket {
		s.handleHttp2Connection(w, r, claims, rule)
		return
	}

	if s.Config.WebsocketProtocol == "ws" {
		upgrader := websocket.Upgrader{
			CheckOrigin: func(r *http.Request) bool { return true },
			// Bounds the 101 response, and is cleared once the upgrade is done.
			HandshakeTimeout: wst.DefaultUpgradeWriteTimeout,
		}
		for _, subprotocol := range strings.Split(r.Header.Get("Sec-WebSocket-Protocol"), ",") {
			if strings.TrimSpace(subprotocol) == "v1" {
				upgrader.Subprotocols = []string{"v1"}
				break
			}
		}

		if claims.Protocol.ReverseDynamic() {
			// The reply is held until a visitor has said what to reach; this
			// handler stays here until the request is over.
			if err := s.rvMgr.HandleDynamicClient(claims, lazyUpgrade{gorilla: func(extra http.Header) (*websocket.Conn, error) {
				return upgrader.Upgrade(w, r, extra)
			}}, r.Context().Done()); err != nil {
				http.Error(w, err.Error(), http.StatusServiceUnavailable)
			}
			return
		}

		wsConn, err := upgrader.Upgrade(w, r, reverseWakeHeader(claims, s.Config.WebsocketPingFrequency))
		if err != nil {
			slog.Error("Gorilla upgrade failed", "err", err)
			return
		}

		slog.Info("Accepted gorilla tunnel", "id", claims.ID, "proto", getProtoName(claims.Protocol), "remote", claims.Remote, "port", claims.Port, "client", r.RemoteAddr, "subprotocol", wsConn.Subprotocol())
		go s.handleGorillaConnection(wsConn, claims, rule)
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

	if claims.Protocol.ReverseDynamic() {
		if err := s.rvMgr.HandleDynamicClient(claims, lazyUpgrade{wst: func(extra http.Header) (*wst.Conn, error) {
			return upgrader.Upgrade(w, r, extra)
		}}, r.Context().Done()); err != nil {
			http.Error(w, err.Error(), http.StatusServiceUnavailable)
		}
		return
	}

	wsConn, err := upgrader.Upgrade(w, r, reverseWakeHeader(claims, s.Config.WebsocketPingFrequency))
	if err != nil {
		slog.Error("Upgrade failed", "err", err)
		return
	}

	slog.Info("Accepted tunnel", "id", claims.ID, "proto", getProtoName(claims.Protocol), "remote", claims.Remote, "port", claims.Port, "client", r.RemoteAddr, "subprotocol", wsConn.Subprotocol())
	go s.handleConnection(wsConn, claims, rule)
}

// logTunnelClosed is deferred by each transport handler; the handler runs for
// the whole life of the tunnel, so this marks its end.
func logTunnelClosed(claims *protocol.JwtTunnelConfig, transport string, start time.Time) {
	slog.Info("Tunnel closed", "id", claims.ID, "transport", transport, "proto", getProtoName(claims.Protocol),
		"remote", claims.Remote, "port", claims.Port, "duration", time.Since(start).Round(time.Millisecond))
}

func (s *Server) handleConnection(wsConn *wst.Conn, claims *protocol.JwtTunnelConfig, rule *RestrictionConfig) {
	defer logTunnelClosed(claims, "websocket", time.Now())
	defer func() { _ = wsConn.Close() }()

	if claims.Protocol.Tun != nil {
		s.serveTun(tun.NewWSTPacketConn(wsConn), claims, rule)
		return
	}

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

		stop, live := tunnel.WatchWst(wsConn, s.Config.WebsocketPingFrequency, "id", claims.ID)
		tunnel.PipeLive(conn, wsConn, live)
		stop()
		return
	}

	// Reverse Tunnel
	if claims.Protocol.ReverseTcp != nil || claims.Protocol.ReverseUnix != nil || claims.Protocol.ReverseUdp != nil {
		s.rvMgr.HandleClient(wsConn, claims)
		return
	}
	if claims.Protocol.ReverseDynamic() {
		slog.Warn("Unsupported reverse protocol", "proto", claims.Protocol)
		return
	}

	slog.Warn("Unsupported protocol", "proto", claims.Protocol)
}

func (s *Server) handleGorillaConnection(wsConn *websocket.Conn, claims *protocol.JwtTunnelConfig, rule *RestrictionConfig) {
	defer logTunnelClosed(claims, "websocket-rfc6455", time.Now())
	defer func() { _ = wsConn.Close() }()

	if claims.Protocol.Tun != nil {
		// NewGorillaPacketConn installs a ping handler that is safe alongside
		// the session's packet writer.
		s.serveTun(tun.NewGorillaPacketConn(wsConn), claims, rule)
		return
	}

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

		stop, live := tunnel.WatchGorilla(wsConn, s.Config.WebsocketPingFrequency, "id", claims.ID)
		tunnel.PipeGorillaLive(conn, wsConn, live)
		stop()
		return
	}

	// Reverse Tunnel
	if claims.Protocol.ReverseTcp != nil || claims.Protocol.ReverseUnix != nil || claims.Protocol.ReverseUdp != nil {
		s.rvMgr.HandleGorillaClient(wsConn, claims)
		return
	}
	if claims.Protocol.ReverseDynamic() {
		slog.Warn("Unsupported reverse protocol (gorilla)", "proto", claims.Protocol)
		return
	}

	slog.Warn("Unsupported protocol (gorilla)", "proto", claims.Protocol)
}

// wtBindAddr is where the WebTransport (UDP) listener binds. For a configured
// port of 0 that is the port the TCP listener was given, so both listen at the
// address the server logs; otherwise it is the configured address as it was.
func wtBindAddr(configured string, tcp net.Addr) string {
	if _, port, err := net.SplitHostPort(configured); err == nil && port == "0" {
		return tcp.String()
	}
	return configured
}

// h2HeaderFlushTimeout bounds sending the held reply of a reverse SOCKS5 request
// over HTTP/2.
const h2HeaderFlushTimeout = 10 * time.Second

func (s *Server) handleHttp2Connection(w http.ResponseWriter, r *http.Request, claims *protocol.JwtTunnelConfig, rule *RestrictionConfig) {
	if claims.Protocol.ReverseDynamic() {
		// The response, and with it the visitor's target, waits for a visitor.
		if err := s.rvMgr.HandleDynamicClient(claims, lazyUpgrade{stream: func(extra http.Header) (io.ReadWriteCloser, error) {
			for k, v := range extra {
				w.Header()[k] = v
			}
			w.WriteHeader(http.StatusOK)
			flusher, _ := w.(http.Flusher)
			if flusher != nil {
				// A peer that stopped reading would block the flush, with the
				// held request's lock taken, so bound it.
				rc := http.NewResponseController(w)
				_ = rc.SetWriteDeadline(time.Now().Add(h2HeaderFlushTimeout))
				err := rc.Flush()
				_ = rc.SetWriteDeadline(time.Time{})
				if err != nil {
					return nil, fmt.Errorf("failed to send the reply: %w", err)
				}
			}
			return &http2ReadWriteCloser{ReadCloser: r.Body, writer: w, flusher: flusher, abortRW: w}, nil
		}}, r.Context().Done()); err != nil {
			http.Error(w, err.Error(), http.StatusServiceUnavailable)
		}
		return
	}

	w.WriteHeader(http.StatusOK)
	if f, ok := w.(http.Flusher); ok {
		f.Flush()
	}

	defer logTunnelClosed(claims, "http2", time.Now())
	slog.Info("Accepted HTTP/2 tunnel", "id", claims.ID, "proto", getProtoName(claims.Protocol), "remote", claims.Remote, "port", claims.Port, "client", r.RemoteAddr)
	var flusher http.Flusher
	if f, ok := w.(http.Flusher); ok {
		flusher = f
	}
	rwc := &http2ReadWriteCloser{
		ReadCloser: r.Body,
		writer:     w,
		flusher:    flusher,
		abortRW:    w,
	}

	if claims.Protocol.Tun != nil {
		// Only tun sessions need Close to unblock a stuck Write. A write
		// deadline in the past resets the stream, which forward and reverse
		// tunnels must not do: they end with a clean END_STREAM.
		rwc.rw = w
		s.serveTun(tun.NewFramedPacketConn(rwc), claims, rule)
		return
	}

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
	if claims.Protocol.ReverseTcp != nil || claims.Protocol.ReverseUnix != nil || claims.Protocol.ReverseUdp != nil {
		s.rvMgr.HandleClientH2(rwc, claims, r.Context().Done())
		return
	}
	slog.Warn("Unsupported protocol for HTTP/2", "proto", claims.Protocol)
	_ = rwc.Close()
}

// admitTun rejects tun sessions unless EnableTun is set. It is checked
// separately from restrictions because an empty protocol list in a rule
// admits every protocol.
func (s *Server) admitTun(claims *protocol.JwtTunnelConfig) error {
	if claims.Protocol.Tun == nil {
		return nil
	}
	if !s.Config.EnableTun {
		return &tunAdmitError{http.StatusForbidden, "tun mode is disabled on this server"}
	}
	if s.ctx.Err() != nil {
		return &tunAdmitError{http.StatusServiceUnavailable, "server is shutting down"}
	}
	// 0 selects the default; anything else below the minimum could not carry
	// IPv6, so refuse it before the connection is upgraded.
	if mtu := claims.Protocol.Tun.Mtu; mtu != 0 && mtu < tun.MinMTU {
		return &tunAdmitError{http.StatusBadRequest, fmt.Sprintf("tun mtu %d is below the minimum %d", mtu, tun.MinMTU)}
	}
	return nil
}

// tunAdmitError is a refusal of a tun session that happens before the
// connection is upgraded, with the HTTP status that describes it.
type tunAdmitError struct {
	status int
	msg    string
}

func (e *tunAdmitError) Error() string { return e.msg }

// tunAdmitStatus is the HTTP status for an admitTun error.
func tunAdmitStatus(err error) int {
	var ae *tunAdmitError
	if errors.As(err, &ae) {
		return ae.status
	}
	return http.StatusForbidden
}

// serveTun runs a tun session until the client disconnects. rule is the
// restriction that admitted the session, or nil when none are configured.
//
// Flows dial like forward tunnels do: tun.DefaultDialTimeout (10s) and no
// SO_MARK, since socket_so_mark only applies to listener sockets.
func (s *Server) serveTun(pc tun.PacketConn, claims *protocol.JwtTunnelConfig, rule *RestrictionConfig) {
	log := slog.With("tunnel_id", claims.ID)
	if s.ctx.Err() != nil {
		_ = pc.Close()
		return
	}
	select {
	case s.tunSessionSlots <- struct{}{}:
		defer func() { <-s.tunSessionSlots }()
	default:
		log.Warn("Tun session refused: server-wide session limit reached", "max_sessions", cap(s.tunSessionSlots))
		_ = pc.Close()
		return
	}
	log.Info("Accepted tun session", "mtu", claims.Protocol.Tun.Mtu)
	err := tun.Serve(s.ctx, pc, tun.Options{
		MTU:             uint32(claims.Protocol.Tun.Mtu),
		Authorize:       func(f tun.Flow) bool { return s.authorizeTunFlow(rule, f) },
		UDPIdleTimeout:  s.Config.TunUdpTimeout,
		SharedFlowSlots: s.tunFlowSlots,
		Logger:          log,
	})
	if err != nil {
		log.Warn("Tun session failed", "err", err)
		return
	}
	log.Info("Tun session closed")
}

// h2CloseGrace is how long a response write may stay blocked after its stream
// was closed normally.
var h2CloseGrace = 10 * time.Second

type http2ReadWriteCloser struct {
	io.ReadCloser
	writer  io.Writer
	flusher http.Flusher
	// rw, when set, lets Close unblock a Write stuck on flow control.
	rw http.ResponseWriter
	// abortRW, when set, lets Abort do the same without Close doing it: a
	// session that ends normally closes its stream cleanly, but one that is cut
	// short must not wait for a peer that stopped reading.
	abortRW http.ResponseWriter
}

// Abort interrupts a Write blocked on the peer's flow-control window, for a
// session that is being cut short.
func (h *http2ReadWriteCloser) Abort() {
	if h.abortRW != nil {
		if err := http.NewResponseController(h.abortRW).SetWriteDeadline(time.Now()); err != nil && !errors.Is(err, http.ErrNotSupported) {
			slog.Debug("HTTP/2 tunnel: could not interrupt writer", "err", err)
		}
	}
}

func (h *http2ReadWriteCloser) Write(p []byte) (int, error) {
	n, err := h.writer.Write(p)
	if err == nil && h.flusher != nil {
		h.flusher.Flush()
	}
	return n, err
}

func (h *http2ReadWriteCloser) Close() error {
	if h.rw != nil {
		// Wake a Write blocked on the peer's flow-control window. Not every
		// ResponseWriter supports deadlines; that is fine.
		err := http.NewResponseController(h.rw).SetWriteDeadline(time.Now())
		if err != nil && !errors.Is(err, http.ErrNotSupported) {
			slog.Debug("HTTP/2 tunnel: could not unblock writer", "err", err)
		}
	} else if h.abortRW != nil {
		// A clean end lets a write in flight finish, but not wait for a peer
		// that ended its request and stopped reading the response: that would
		// hold the pipe and the session behind it.
		err := http.NewResponseController(h.abortRW).SetWriteDeadline(time.Now().Add(h2CloseGrace))
		if err != nil && !errors.Is(err, http.ErrNotSupported) {
			slog.Debug("HTTP/2 tunnel: could not bound writer", "err", err)
		}
	}
	return h.ReadCloser.Close()
}

// reverseWakeHeader tells a Go client that this server sends a wake-up frame
// when it uses a parked reverse connection. Older servers do not, and clients
// must dial their target eagerly against them. For reverse UDP the first
// datagram is the wake-up: the client dials its target and forwards it.
func reverseWakeHeader(claims *protocol.JwtTunnelConfig, ping time.Duration) http.Header {
	if claims.Protocol.ReverseTcp == nil && claims.Protocol.ReverseUnix == nil && claims.Protocol.ReverseUdp == nil {
		return nil
	}
	h := http.Header{ReverseWakeHeader: []string{"1"}}
	if ping > 0 {
		// The server pings parked connections at this interval; a client that
		// hears nothing for several intervals knows the connection is dead.
		h.Set(ReversePingHeader, strconv.FormatInt(ping.Milliseconds(), 10))
	}
	return h
}

// ReverseWakeHeader is the response header advertising the wake-up frame.
const ReverseWakeHeader = "X-Wstunnel-Reverse-Wake"

// ReversePingHeader carries the interval, in milliseconds, at which the server
// pings a parked reverse connection. It is absent when pings are disabled.
const ReversePingHeader = "X-Wstunnel-Reverse-Ping"
