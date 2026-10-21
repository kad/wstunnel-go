package client

import (
	"bufio"
	"context"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/gorilla/websocket"
	"github.com/kad/wstunnel-go/pkg/protocol"
	"github.com/kad/wstunnel-go/pkg/tunnel"
	"github.com/kad/wstunnel-go/pkg/wst"
)

type Config struct {
	ServerURL                              string            `yaml:"remote_addr"`
	PathPrefix                             string            `yaml:"http_upgrade_path_prefix"`
	JWTSecret                              string            `yaml:"jwt_secret"`
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
	WebsocketProtocol                      string            `yaml:"mode"` // "rust" or "ws"
}

type Client struct {
	Config   Config
	pool     *ConnectionPool
	wtClient *WebTransportClient

	reverseBackoff sharedBackoff

	// fullTunnelMark is the fwmark a full tunnel (route=default, fwmark mode)
	// forces onto the client's own sockets; 0 means use Config.SocketSoMark. It
	// is set after the client is built, so it cannot live in Config.
	fullTunnelMark atomic.Uint32
	// resolver, when set, resolves the server name instead of the system
	// resolver (full tunnel, fwmark mode: its sockets carry the mark).
	resolver atomic.Pointer[net.Resolver]
	// serverAddrs, when set (full tunnel), are the addresses the tunnel server
	// name resolved to when the loop guard last passed. Every transport dials
	// these instead of resolving the name again, so a reconnect works while DNS
	// is unreachable, while the name still decides TLS SNI/verification, the
	// HTTP Host and the websocket URL.
	serverAddrs atomic.Pointer[[]netip.Addr]
	// setMark replaces socket.SetSoMark (tests); set before the client dials.
	setMark func(fd uintptr, mark uint32) error
}

// pinnedTargets returns, for a dial of addr ("host:port"), the "ip:port"
// targets to try in order when addr names the tunnel server and its addresses
// are pinned, and nil when the normal resolution applies.
func (c *Client) pinnedTargets(addr string) []string {
	ips := c.serverAddrs.Load()
	if ips == nil || len(*ips) == 0 {
		return nil
	}
	u, err := url.Parse(c.Config.ServerURL)
	if err != nil {
		return nil
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil || !strings.EqualFold(host, u.Hostname()) {
		return nil
	}
	targets := make([]string, 0, len(*ips))
	for _, ip := range *ips {
		targets = append(targets, net.JoinHostPort(ip.String(), port))
	}
	return targets
}

// pinnedAttemptFloor is the least time one pinned address gets, when the
// deadline allows it.
const pinnedAttemptFloor = 2 * time.Second

// dialPinned dials addr with d, trying the pinned server addresses in order
// when there are any; the first connection that succeeds wins. The dial
// deadline (d.Timeout and the context's) is shared out: each attempt gets the
// remaining time divided by the addresses still to try (at least
// pinnedAttemptFloor, never more than what is left), so an address that drops
// packets cannot use up the deadline before the next one is tried.
func (c *Client) dialPinned(ctx context.Context, d *net.Dialer, network, addr string) (net.Conn, error) {
	targets := c.pinnedTargets(addr)
	if targets == nil {
		return d.DialContext(ctx, network, addr)
	}
	var deadline time.Time
	if d.Timeout > 0 {
		deadline = time.Now().Add(d.Timeout)
	}
	if dl, ok := ctx.Deadline(); ok && (deadline.IsZero() || dl.Before(deadline)) {
		deadline = dl
	}
	var errs []error
	for i, t := range targets {
		attempt := *d
		if !deadline.IsZero() {
			remaining := time.Until(deadline)
			if remaining <= 0 {
				errs = append(errs, context.DeadlineExceeded)
				break
			}
			slice := min(max(remaining/time.Duration(len(targets)-i), pinnedAttemptFloor), remaining)
			attempt.Timeout, attempt.Deadline = slice, time.Time{}
		}
		conn, err := attempt.DialContext(ctx, network, t)
		if err == nil {
			return conn, nil
		}
		errs = append(errs, err)
		if ctx.Err() != nil {
			break
		}
	}
	return nil, errors.Join(errs...)
}

// socketMark is the SO_MARK for the client's own sockets, 0 for none.
func (c *Client) socketMark() uint32 {
	if m := c.fullTunnelMark.Load(); m != 0 {
		return m
	}
	return c.Config.SocketSoMark
}

const legacyJWTSecret = "champignonfrais"

var legacyJWTSecretWarning sync.Once

func NewClient(config Config) *Client {
	c := &Client{Config: config}
	c.wtClient = NewWebTransportClient(c)
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

	secret := c.Config.JWTSecret
	if secret == "" {
		secret = legacyJWTSecret
		legacyJWTSecretWarning.Do(func() {
			slog.Warn("Using legacy default JWT secret for Rust compatibility; configure jwt_secret for secure deployments")
		})
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(secret))
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
	// Ensure port is set before scheme rewrite
	if u.Port() == "" {
		if u.Scheme == "wss" || u.Scheme == "https" {
			u.Host = net.JoinHostPort(u.Hostname(), "443")
		} else {
			u.Host = net.JoinHostPort(u.Hostname(), "80")
		}
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
		HandshakeTimeout: replyTimeout(p),
	}

	// Use pool if available, or dial transport directly
	var connected atomic.Bool
	dialer.NetDialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		var conn net.Conn
		var err error
		if c.pool != nil {
			conn, err = c.pool.Get(ctx)
		} else {
			conn, err = c.dialTransport(ctx, network, addr)
		}
		connected.Store(err == nil)
		return conn, err
	}

	conn, resp, err := dialer.Dial(u.String(), header)
	if err != nil {
		return nil, resp, fmt.Errorf("failed to dial: %w", markReplyTimeout(err, connected.Load()))
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
	// Ensure port is set before scheme rewrite
	if u.Port() == "" {
		if u.Scheme == "wss" || u.Scheme == "https" {
			u.Host = net.JoinHostPort(u.Hostname(), "443")
		} else {
			u.Host = net.JoinHostPort(u.Hostname(), "80")
		}
	}
	switch u.Scheme {
	case "ws":
		u.Scheme = "http"
	case "wss":
		u.Scheme = "https"
	}
	u.Path = fmt.Sprintf("/%s/events", c.Config.PathPrefix)

	pr, pw := io.Pipe()
	// The request context lives as long as the tunnel: the stream is cancelled
	// when it is closed. For a request answered only when a visitor shows up, it
	// is also cancelled if no reply comes in time. http.Transport's own
	// ResponseHeaderTimeout would not do: it starts once the request body is
	// written, and this body stays open for the whole tunnel.
	ctx, cancel := context.WithCancel(context.Background())
	var replyTimedOut, connected atomic.Bool
	var replyTimer *time.Timer
	if holdsReply(p) {
		replyTimer = time.AfterFunc(reverseReplyTimeout, func() {
			replyTimedOut.Store(true)
			cancel()
		})
	}
	req, err := http.NewRequestWithContext(ctx, "POST", u.String(), pr)
	if err != nil {
		cancel()
		if replyTimer != nil {
			replyTimer.Stop()
		}
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

	protocols := new(http.Protocols)
	protocols.SetHTTP2(true)
	protocols.SetUnencryptedHTTP2(true)
	tr := &http.Transport{
		Protocols: protocols,
		// One transport per tunnel, so nothing reuses its connection. Without
		// this the connection stays open and idle after the tunnel ends, or after
		// a held request is cancelled, and they pile up on both peers.
		DisableKeepAlives: true,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			conn, err := c.dialTransport(ctx, network, addr)
			connected.Store(err == nil)
			return conn, err
		},
		DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			// cfg is ignored on purpose: the client's own TLS settings (SNI
			// override, mTLS material, verification policy) come from Config.
			// Its ALPN list must still be honoured, otherwise the server
			// negotiates HTTP/1.1 and never routes to the HTTP/2 handler.
			conn, err := c.dialTransport(ctx, network, addr, "h2")
			connected.Store(err == nil)
			return conn, err
		},
	}
	if p.Tun != nil && c.Config.PingFrequency > 0 {
		// A tun session is long-lived and must notice a peer that vanished
		// without closing the connection, like the websocket watchdog does:
		// after one ping interval without a frame the transport sends a PING
		// and closes the connection if it is not answered within two more,
		// three intervals in total. Closing fails the stream, so the session
		// loop reconnects. Other HTTP/2 tunnels are left as they were.
		tr.HTTP2 = &http.HTTP2Config{
			SendPingTimeout: c.Config.PingFrequency,
			PingTimeout:     2 * c.Config.PingFrequency,
		}
	}
	httpClient := &http.Client{Transport: tr}

	resp, err := httpClient.Do(req)
	// The reply, or its absence, is settled: from here the timer must not cut
	// an established tunnel short.
	timedOut := replyTimer != nil && (!replyTimer.Stop() || replyTimedOut.Load())
	if err != nil || timedOut {
		cancel()
		tr.CloseIdleConnections()
		_ = pw.Close()
		if resp != nil {
			_ = resp.Body.Close()
		}
		if timedOut {
			// The timer also runs while the connection is being made; only
			// running out once connected means the server is just waiting for
			// a visitor.
			err = markReplyTimeout(os.ErrDeadlineExceeded, connected.Load())
			return nil, nil, fmt.Errorf("no reply within %v: %w", reverseReplyTimeout, err)
		}
		return nil, nil, fmt.Errorf("failed to send request: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		cancel()
		_ = pw.Close()
		_ = resp.Body.Close()
		tr.CloseIdleConnections()
		return nil, resp, fmt.Errorf("server rejected request: %s", resp.Status)
	}

	return &tunnelReadWriteCloser{
		ReadCloser: resp.Body,
		Writer:     pw,
		cancel:     func() { cancel(); tr.CloseIdleConnections() },
	}, resp, nil
}

type tunnelReadWriteCloser struct {
	io.ReadCloser
	io.Writer
	cancel context.CancelFunc // ends the request when the stream is closed
}

func (t *tunnelReadWriteCloser) Close() error {
	if t.cancel != nil {
		defer t.cancel()
	}
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
	ws      *wst.Conn
	gorilla *websocket.Conn
	h2      io.ReadWriteCloser
	wt      io.ReadWriteCloser
	r       *http.Response
	err     error
}

func (ts *tunnelStream) Close() {
	if ts.ws != nil {
		_ = ts.ws.Close()
	}
	if ts.gorilla != nil {
		_ = ts.gorilla.Close()
	}
	if ts.h2 != nil {
		_ = ts.h2.Close()
	}
	if ts.wt != nil {
		_ = ts.wt.Close()
	}
}

func (c *Client) connectToGorilla(p protocol.LocalProtocol, remoteHost string, remotePort uint16) (*websocket.Conn, *http.Response, error) {
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
	case "ws", "http":
		u.Scheme = "ws"
	case "wss", "https":
		u.Scheme = "wss"
	}
	u.Path = fmt.Sprintf("/%s/events", c.Config.PathPrefix)

	header := http.Header{}
	// For RFC compliant mode, we might want to use standard headers or follow same JWT pattern
	// The TODO says "only go clients will be able to work in that mode"
	header.Set("Sec-WebSocket-Protocol", fmt.Sprintf("v1, %s%s", protocol.JwtHeaderPrefix, token))

	for k, v := range c.Config.Headers {
		header.Set(k, v)
	}
	fileHeaders := c.loadHttpHeaders()
	for k, v := range fileHeaders {
		header.Set(k, v)
	}
	if c.Config.HttpUpgradeCredentials != "" {
		header.Set("Authorization", c.Config.HttpUpgradeCredentials)
	}

	dialer := &websocket.Dialer{
		HandshakeTimeout: replyTimeout(p),
	}
	isTLS := u.Scheme == "wss"
	if isTLS {
		if _, err := c.tlsClientConfig(u.Hostname()); err != nil {
			return nil, nil, err
		}
	}

	// The TLS handshake is done in the dial hook, so that once it returns the
	// only thing left to wait for is the server's reply.
	var connected atomic.Bool
	track := func(conn net.Conn, err error) (net.Conn, error) {
		connected.Store(err == nil)
		return conn, err
	}
	if c.pool != nil && !isTLS {
		dialer.NetDialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
			return track(c.pool.Get(ctx))
		}
	} else if isTLS {
		dialer.NetDialTLSContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
			return track(c.dialTransport(ctx, network, addr))
		}
	} else {
		dialer.NetDialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
			conn, _, _, err := c.dialRawTransport(ctx, network, addr)
			return track(conn, err)
		}
	}

	conn, resp, err := dialer.Dial(u.String(), header)
	if err != nil {
		err = markReplyTimeout(err, connected.Load())
		if resp != nil {
			err = fmt.Errorf("%w (server replied %s)", err, resp.Status)
		}
	}
	return conn, resp, err
}

func (c *Client) connectToTransport(p protocol.LocalProtocol, remoteHost string, remotePort uint16) *tunnelStream {
	u, err := url.Parse(c.Config.ServerURL)
	if err != nil {
		return &tunnelStream{err: fmt.Errorf("invalid server URL: %w", err)}
	}

	if u.Scheme == "wt" || u.Scheme == "wts" {
		wt, resp, err := c.wtClient.Connect(p, remoteHost, remotePort)
		return &tunnelStream{wt: wt, r: resp, err: err}
	}

	if u.Scheme == "http" || u.Scheme == "https" {
		h2, resp, err := c.connectToHttp2(p, remoteHost, remotePort)
		return &tunnelStream{h2: h2, r: resp, err: err}
	}

	if c.Config.WebsocketProtocol == "ws" {
		ws, resp, err := c.connectToGorilla(p, remoteHost, remotePort)
		return &tunnelStream{gorilla: ws, r: resp, err: err}
	}

	ws, resp, err := c.connectToWstunnel(p, remoteHost, remotePort)
	return &tunnelStream{ws: ws, r: resp, err: err}
}

func (c *Client) startPipe(local net.Conn, ts *tunnelStream) {
	c.startPipeMode(local, ts, true)
}

// startPipeMode pipes local and the tunnel. With enforce the client closes a
// server that stays silent for three ping intervals. Without it the client only
// keeps pinging, for a reverse connection dialed eagerly against a server that
// does not announce the wake-up frame: such a server may be keeping it parked
// without reading it, and so never answers a ping.
func (c *Client) startPipeMode(local net.Conn, ts *tunnelStream, enforce bool) {
	defer ts.Close()

	watchWst, watchGorilla := tunnel.WatchWst, tunnel.WatchGorilla
	if !enforce {
		watchWst, watchGorilla = tunnel.PingWst, tunnel.PingGorilla
	}
	if ts.ws != nil {
		stop, live := watchWst(ts.ws, c.Config.PingFrequency, "role", "client")
		defer stop()
		tunnel.PipeLive(local, ts.ws, live)
	} else if ts.gorilla != nil {
		stop, live := watchGorilla(ts.gorilla, c.Config.PingFrequency, "role", "client")
		defer stop()
		tunnel.PipeGorillaLive(local, ts.gorilla, live)
	} else if ts.wt != nil {
		if framed, ok := ts.wt.(*protocol.FramedUDPReadWriteCloser); ok {
			tunnel.PipeUDP(local, framed)
		} else {
			tunnel.PipeBiDir(local, ts.wt)
		}
	} else {
		tunnel.PipeBiDir(local, ts.h2)
	}
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

	slog.Info("Unix Listener started", "path", listener.Addr().String(), "server", c.Config.ServerURL)

	for {
		conn, err := listener.Accept()
		if err != nil {
			slog.Warn("Unix: failed to accept", "err", err)
			continue
		}

		go func(netConn net.Conn) {
			defer func() { _ = netConn.Close() }()
			ts := c.connectToTransport(ltr.Protocol, ltr.Remote, ltr.Port)
			if ts.err != nil {
				slog.Error("Failed to connect to transport for Unix", "err", ts.err)
				return
			}
			c.startPipe(netConn, ts)
		}(conn)
	}
}

func containsSocks5Method(methods []byte, want byte) bool {
	for _, method := range methods {
		if method == want {
			return true
		}
	}
	return false
}

func authenticateHTTPProxy(header string, credentials *protocol.Credentials) bool {
	if credentials == nil {
		return true
	}

	header = strings.TrimSpace(header)
	if header == "" {
		return false
	}

	parts := strings.SplitN(header, " ", 2)
	if len(parts) != 2 {
		return false
	}
	if !strings.EqualFold(parts[0], "Basic") {
		return false
	}

	payload, err := base64.StdEncoding.DecodeString(strings.TrimSpace(parts[1]))
	if err != nil {
		return false
	}

	expected := credentials.Username + ":" + credentials.Password
	return constantTimeEqualBytes(payload, []byte(expected))
}

func constantTimeEqualBytes(actual, expected []byte) bool {
	maxLen := len(actual)
	if len(expected) > maxLen {
		maxLen = len(expected)
	}

	diff := int32(len(actual) ^ len(expected))
	for i := 0; i < maxLen; i++ {
		var a, b byte
		if i < len(actual) {
			a = actual[i]
		}
		if i < len(expected) {
			b = expected[i]
		}
		diff |= int32(a ^ b)
	}

	return subtle.ConstantTimeEq(diff, 0) == 1
}

// reverseMinParked is how long a reverse connection must stay up before its end
// counts as routine. One that the server drops sooner was refused.
const reverseMinParked = 5 * time.Second

// reverseReplyTimeout is how long a reverse request that is answered only when a
// visitor asks for something may wait for its reply, as in Rust.
var reverseReplyTimeout = 30 * time.Second

// holdsReply reports whether a server may keep the reply to a request for p
// until a visitor shows up. A Rust server does so for every reverse tunnel,
// and a Go one for reverse SOCKS5, whose reply carries the visitor's target.
func holdsReply(p protocol.LocalProtocol) bool {
	return p.ReverseTcp != nil || p.ReverseUdp != nil || p.ReverseDynamic()
}

// replyTimeout is how long a request for p may wait for the server's reply.
func replyTimeout(p protocol.LocalProtocol) time.Duration {
	if holdsReply(p) {
		return reverseReplyTimeout
	}
	return 10 * time.Second
}

// parseTargetCookie reads the target a server named in its reply: a JWT whose
// claims are the protocol, host and port to connect to. The signature is not
// checked, as in Rust. The host loses the brackets Rust puts around IPv6. A reply without a host, a
// port, or a single TCP or UDP protocol is not a target.
func parseTargetCookie(cookie string) (host string, port uint16, proto protocol.LocalProtocol, ok bool) {
	if cookie == "" {
		return "", 0, protocol.LocalProtocol{}, false
	}
	claims := &protocol.JwtTunnelConfig{}
	if _, _, err := jwt.NewParser().ParseUnverified(cookie, claims); err != nil || claims.Remote == "" || claims.Port == 0 {
		return "", 0, protocol.LocalProtocol{}, false
	}
	// A target is dialed over TCP or UDP, and exactly one of them.
	if claims.Protocol.Variants() != 1 || (claims.Protocol.Tcp == nil && claims.Protocol.Udp == nil) {
		return "", 0, protocol.LocalProtocol{}, false
	}
	host = strings.TrimSuffix(strings.TrimPrefix(claims.Remote, "["), "]")
	return host, claims.Port, claims.Protocol, true
}

// errReplyTimeout marks a request that connected but got no reply in time. For
// a reverse SOCKS5 request that only means no visitor came; a timeout while
// connecting is a failure like any other.
var errReplyTimeout = errors.New("no reply from the server")

// markReplyTimeout tags err as errReplyTimeout if it is a timeout that happened
// after the connection was made.
func markReplyTimeout(err error, connected bool) error {
	if connected && isTimeout(err) {
		return fmt.Errorf("%w: %w", errReplyTimeout, err)
	}
	return err
}

// isTimeout reports whether err is a deadline or timeout of any kind.
func isTimeout(err error) bool {
	var ne net.Error
	return errors.Is(err, context.DeadlineExceeded) || errors.Is(err, os.ErrDeadlineExceeded) ||
		(errors.As(err, &ne) && ne.Timeout())
}

// socks5HandshakeTimeout is how long a SOCKS5 client has to finish its greeting
// and request once connected, as in Rust (#515). A real client sends them at
// once; a silent one would otherwise hold a goroutine and a descriptor forever.
var socks5HandshakeTimeout = 10 * time.Second

// handleSocks5Bounded is handleSocks5 under the handshake timeout. The deadline
// is cleared again so the tunnel that follows is not bound by it.
func (c *Client) handleSocks5Bounded(conn net.Conn, credentials *protocol.Credentials) (string, uint16, func(byte) error, error) {
	_ = conn.SetDeadline(time.Now().Add(socks5HandshakeTimeout))
	defer func() { _ = conn.SetDeadline(time.Time{}) }()
	return c.handleSocks5(conn, credentials)
}

func (c *Client) handleSocks5(conn net.Conn, credentials *protocol.Credentials) (string, uint16, func(byte) error, error) {
	buf := make([]byte, 256)

	// 1. Version/Methods
	if _, err := io.ReadFull(conn, buf[:2]); err != nil {
		return "", 0, nil, err
	}
	if buf[0] != 0x05 {
		return "", 0, nil, fmt.Errorf("invalid socks version: %d", buf[0])
	}
	nmethods := int(buf[1])
	if _, err := io.ReadFull(conn, buf[:nmethods]); err != nil {
		return "", 0, nil, err
	}

	methods := buf[:nmethods]
	selectedMethod := byte(0x00)
	if credentials != nil {
		selectedMethod = 0x02
	}
	if !containsSocks5Method(methods, selectedMethod) {
		if _, err := conn.Write([]byte{0x05, 0xFF}); err != nil {
			return "", 0, nil, err
		}
		return "", 0, nil, fmt.Errorf("no acceptable authentication method")
	}

	if _, err := conn.Write([]byte{0x05, selectedMethod}); err != nil {
		return "", 0, nil, err
	}

	if selectedMethod == 0x02 {
		if _, err := io.ReadFull(conn, buf[:2]); err != nil {
			return "", 0, nil, err
		}
		if buf[0] != 0x01 {
			return "", 0, nil, fmt.Errorf("unsupported socks auth version: %d", buf[0])
		}

		ulen := int(buf[1])
		if _, err := io.ReadFull(conn, buf[:ulen]); err != nil {
			return "", 0, nil, err
		}
		username := string(buf[:ulen])

		if _, err := io.ReadFull(conn, buf[:1]); err != nil {
			return "", 0, nil, err
		}
		plen := int(buf[0])
		if _, err := io.ReadFull(conn, buf[:plen]); err != nil {
			return "", 0, nil, err
		}
		password := string(buf[:plen])

		status := byte(0x00)
		if !constantTimeEqualBytes([]byte(username), []byte(credentials.Username)) ||
			!constantTimeEqualBytes([]byte(password), []byte(credentials.Password)) {
			status = 0x01
		}
		if _, err := conn.Write([]byte{0x01, status}); err != nil {
			return "", 0, nil, err
		}
		if status != 0x00 {
			return "", 0, nil, fmt.Errorf("invalid socks5 credentials")
		}
	}

	// 2. Request
	if _, err := io.ReadFull(conn, buf[:4]); err != nil {
		return "", 0, nil, err
	}
	if buf[0] != 0x05 || buf[1] != 0x01 {
		return "", 0, nil, fmt.Errorf("unsupported socks command: %d", buf[1])
	}

	var host string
	switch buf[3] {
	case 0x01: // IPv4
		if _, err := io.ReadFull(conn, buf[:4]); err != nil {
			return "", 0, nil, err
		}
		host = net.IP(buf[:4]).String()
	case 0x03: // Domain
		if _, err := io.ReadFull(conn, buf[:1]); err != nil {
			return "", 0, nil, err
		}
		sz := int(buf[0])
		if _, err := io.ReadFull(conn, buf[:sz]); err != nil {
			return "", 0, nil, err
		}
		host = string(buf[:sz])
	case 0x04: // IPv6
		if _, err := io.ReadFull(conn, buf[:16]); err != nil {
			return "", 0, nil, err
		}
		host = net.IP(buf[:16]).String()
	default:
		return "", 0, nil, fmt.Errorf("unsupported address type: %d", buf[3])
	}

	if _, err := io.ReadFull(conn, buf[:2]); err != nil {
		return "", 0, nil, err
	}
	port := binary.BigEndian.Uint16(buf[:2])

	replyFunc := func(rep byte) error {
		resp := []byte{0x05, rep, 0x00, 0x01, 0, 0, 0, 0, 0, 0}
		_, err := conn.Write(resp)
		return err
	}

	return host, port, replyFunc, nil
}

func (c *Client) runSocks5Tunnel(ltr *protocol.LocalToRemote) {
	listener, err := net.Listen("tcp", ltr.Local)
	if err != nil {
		slog.Error("SOCKS5: failed to listen", "local", ltr.Local, "err", err)
		return
	}
	defer func() { _ = listener.Close() }()

	slog.Info("SOCKS5 Listener started", "local", listener.Addr().String(), "server", c.Config.ServerURL)

	for {
		conn, err := listener.Accept()
		if err != nil {
			slog.Warn("SOCKS5: failed to accept", "err", err)
			continue
		}

		go func(netConn net.Conn) {
			defer func() { _ = netConn.Close() }()
			var credentials *protocol.Credentials
			if ltr.Protocol.Socks5 != nil {
				credentials = ltr.Protocol.Socks5.Credentials
			}
			targetHost, targetPort, replyFunc, err := c.handleSocks5Bounded(netConn, credentials)
			if err != nil {
				slog.Warn("SOCKS5 handshake failed", "err", err)
				return
			}

			// For forward SOCKS5, the server just needs to open a TCP connection to the target
			tcpProto := protocol.LocalProtocol{Tcp: &protocol.TcpProtocol{ProxyProtocol: false}}
			ts := c.connectToTransport(tcpProto, targetHost, targetPort)
			if ts.err != nil {
				slog.Error("Failed to connect to transport for SOCKS5", "err", ts.err)
				_ = replyFunc(0x01)
				return
			}
			if err := replyFunc(0x00); err != nil {
				slog.Warn("Failed to send SOCKS5 reply", "err", err)
				ts.Close()
				return
			}
			c.startPipe(netConn, ts)
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

	slog.Info("HTTP Proxy Listener started", "local", listener.Addr().String(), "server", c.Config.ServerURL)

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

	var credentials *protocol.Credentials
	if ltr.Protocol.HttpProxy != nil {
		credentials = ltr.Protocol.HttpProxy.Credentials
	}
	if !authenticateHTTPProxy(req.Header.Get("Proxy-Authorization"), credentials) {
		resp := "HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"wstunnel-go\"\r\n\r\n"
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
	c.startPipe(conn, ts)
}

func (c *Client) StartReverseTunnel(ltr *protocol.LocalToRemote) {
	maxDelay := c.Config.ReverseTunnelConnectionRetryMaxBackoff
	if maxDelay == 0 {
		maxDelay = 10 * time.Second
	}

	// The server listens on the address carried in the JWT, so for reverse TCP
	// that is the bind side of the argument; the target is dialed locally.
	listenHost, listenPort := ltr.Remote, ltr.Port
	if ltr.Protocol.ReverseTcp != nil || ltr.Protocol.ReverseUdp != nil || ltr.Protocol.ReverseDynamic() {
		h, ps, err := net.SplitHostPort(ltr.Local)
		pn, perr := strconv.ParseUint(ps, 10, 16)
		if err != nil || perr != nil {
			slog.Error("Reverse tunnel: invalid listen address", "local", ltr.Local)
			return
		}
		listenHost, listenPort = h, uint16(pn)
	}

	// A SOCKS5 tunnel names its target per visitor, so the server answers the
	// request only when a visitor has asked for something. That reply can take as
	// long as there is no visitor, and running out of patience is not a failure.
	dynamic := ltr.Protocol.ReverseDynamic()

	for {
		c.reverseBackoff.wait()
		started := time.Now()
		ts := c.connectToTransport(ltr.Protocol, listenHost, listenPort)
		if ts.err != nil && errors.Is(ts.err, errReplyTimeout) {
			slog.Debug("Reverse tunnel: no visitor within the reply timeout, asking again", "timeout", reverseReplyTimeout)
			continue
		}
		if ts.err != nil {
			// All reverse tunnels share one backoff; only the first failure of
			// a round is logged.
			wait, escalated := c.reverseBackoff.fail(started, maxDelay)
			if escalated {
				slog.Error("Reverse tunnel: failed to connect to transport", "err", ts.err, "retry_in", wait.Round(10*time.Millisecond))
			}
			continue
		}

		// Check for target in cookies (for dynamic reverse tunnels)
		targetHost := ltr.Remote
		targetPort := ltr.Port
		targetProto := ltr.Protocol

		// Rust sends the target in a Cookie response header (some servers in
		// Set-Cookie). Its host is bracketed for IPv6, which net.Dial does not want.
		var cookieStr string
		if ts.r != nil {
			if cookieStr = ts.r.Header.Get("Cookie"); cookieStr == "" {
				cookieStr = ts.r.Header.Get("Set-Cookie")
			}
		}
		h, p, proto, parsed := parseTargetCookie(cookieStr)
		if parsed {
			targetHost, targetPort, targetProto = h, p, proto
		}
		if dynamic && !parsed {
			// A server that answers without a usable target is failing the
			// request. Back off like any other failure instead of asking again at
			// once, and do not dial the placeholder address of the tunnel.
			wait, escalated := c.reverseBackoff.fail(started, maxDelay)
			if escalated {
				slog.Error("Reverse SOCKS5: the server's reply carries no usable target", "retry_in", wait.Round(10*time.Millisecond))
			}
			ts.Close()
			continue
		}

		// Wait until the server has a connection to hand us, so the local
		// target is only dialed on demand. Only websocket streams from a
		// server that advertises the wake-up frame are lazy; others dial eagerly.
		var (
			firstData []byte
			lazy      bool
			err       error
		)
		connected := time.Now()
		if dynamic {
			// Answered only for a visitor, so the connection is in use already.
			lazy = true
		} else if firstData, lazy, err = c.awaitReverseTrigger(ts, ltr.Protocol.ReverseUdp != nil); err != nil {
			slog.Debug("Reverse tunnel: parked connection ended before use", "err", err)
			ts.Close()
			if time.Since(connected) < reverseMinParked {
				// The server took the request and dropped it at once: it could
				// not set the listener up (the port is taken, say). Back off
				// instead of asking again straight away. A connection that
				// stayed parked for a while and was then reaped is routine.
				wait, escalated := c.reverseBackoff.fail(started, maxDelay)
				if escalated {
					slog.Error("Reverse tunnel: the server dropped the connection at once", "err", err, "retry_in", wait.Round(10*time.Millisecond))
				}
			} else {
				c.reverseBackoff.success()
			}
			continue
		}
		c.reverseBackoff.success()

		serve := func() {
			var (
				localConn net.Conn
				err       error
			)
			if targetProto.Unix != nil || targetProto.ReverseUnix != nil {
				path := ""
				if targetProto.Unix != nil {
					path = targetProto.Unix.Path
				} else {
					path = targetProto.ReverseUnix.Path
				}
				localConn, err = net.Dial("unix", path)
			} else if targetProto.ReverseUdp != nil || targetProto.Udp != nil {
				// The "connection" to a UDP target is a connected socket: each
				// message from the tunnel is one datagram to it, and each
				// datagram it answers with is one message back.
				localConn, err = net.Dial("udp", net.JoinHostPort(targetHost, fmt.Sprintf("%d", targetPort)))
			} else {
				localConn, err = net.Dial("tcp", net.JoinHostPort(targetHost, fmt.Sprintf("%d", targetPort)))
			}

			if err != nil {
				slog.Error("Reverse tunnel: failed to connect to local destination", "host", targetHost, "port", targetPort, "err", err)
				ts.Close()
				return
			}

			// The first datagram of a reverse UDP tunnel is the trigger and goes
			// to the target even when it is empty; on a stream an empty wake-up
			// frame carries nothing.
			if len(firstData) > 0 || ltr.Protocol.ReverseUdp != nil {
				if _, err := localConn.Write(firstData); err != nil {
					slog.Error("Reverse tunnel: failed to write to local destination", "err", err)
					_ = localConn.Close()
					ts.Close()
					return
				}
			}

			slog.Info("Reverse tunnel established", "target_host", targetHost, "target_port", targetPort)
			// Only a connection the server woke up is known to be read by it.
			c.startPipeMode(localConn, ts, lazy)
			slog.Info("Reverse tunnel closed")
		}
		if lazy {
			// Park the next connection right away so parallel inbound
			// connections each get their own tunnel.
			go serve()
		} else {
			serve()
		}
	}
}

// awaitReverseTrigger blocks until the server starts using a parked reverse
// connection. The first binary frame is the trigger; the Go server sends an
// empty one when it accepts a connection, and any payload is returned so it
// can be forwarded to the target.
//
// A reverse UDP tunnel always waits, whatever the server says: the peer talks
// first, so its first datagram is the trigger on any server, and the client can
// then park the next connection for the next peer.
func (c *Client) awaitReverseTrigger(ts *tunnelStream, udp bool) (data []byte, lazy bool, err error) {
	woken := ts.r != nil && ts.r.Header.Get("X-Wstunnel-Reverse-Wake") != ""
	if !woken && !udp {
		return nil, false, nil
	}
	// A server that advertises its ping interval pings the parked connection,
	// so silence for several intervals means the path or the server is gone.
	// Without this the read below would wait for TCP to notice, if it ever does.
	var silence time.Duration
	if ts.r != nil {
		if ms, perr := strconv.ParseInt(ts.r.Header.Get("X-Wstunnel-Reverse-Ping"), 10, 64); perr == nil && ms > 0 {
			silence = 3 * time.Duration(ms) * time.Millisecond
		}
	}
	switch {
	case ts.h2 != nil || ts.wt != nil:
		rwc := ts.h2
		if ts.wt != nil {
			rwc = ts.wt
		}
		if pr, ok := rwc.(interface{ ReadPacket() ([]byte, error) }); ok {
			p, err := pr.ReadPacket()
			return p, true, err
		}
		buf := make([]byte, 64*1024)
		n, err := rwc.Read(buf)
		if n > 0 {
			return buf[:n], true, nil
		}
		return nil, true, err
	case ts.ws != nil:
		// ReadMessage answers pings itself and never returns for them, so the
		// deadline is refreshed from the ping handler as well as per message.
		arm := func() {
			if silence > 0 {
				_ = ts.ws.SetReadDeadline(time.Now().Add(silence))
			}
		}
		// No pong when the server announced its pings: it does not read a
		// parked connection, so replies would only pile up in its receive
		// buffer until a visitor arrives. Any other server gets the default.
		if silence > 0 {
			ts.ws.SetPingHandler(func(string) error {
				arm()
				return nil
			})
		}
		// The pipe that follows must not inherit the parked-phase handler or
		// the silence deadline.
		defer func() {
			ts.ws.SetPingHandler(nil)
			if silence > 0 {
				_ = ts.ws.SetReadDeadline(time.Time{})
			}
		}()
		for {
			arm()
			mt, p, err := ts.ws.ReadMessage()
			if err != nil {
				return nil, true, err
			}
			if mt == wst.BinaryMessage {
				return p, true, nil
			}
		}
	case ts.gorilla != nil:
		arm := func() {
			if silence > 0 {
				_ = ts.gorilla.SetReadDeadline(time.Now().Add(silence))
			}
		}
		if silence > 0 {
			ts.gorilla.SetPingHandler(func(string) error {
				arm()
				return nil
			})
		}
		defer func() {
			ts.gorilla.SetPingHandler(nil)
			if silence > 0 {
				_ = ts.gorilla.SetReadDeadline(time.Time{})
			}
		}()
		for {
			arm()
			mt, p, err := ts.gorilla.ReadMessage()
			if err != nil {
				return nil, true, err
			}
			if mt == websocket.BinaryMessage {
				return p, true, nil
			}
		}
	}
	return nil, false, nil
}

func (c *Client) runTcpTunnel(ltr *protocol.LocalToRemote) {
	listener, err := net.Listen("tcp", ltr.Local)
	if err != nil {
		slog.Error("Failed to listen", "local", ltr.Local, "err", err)
		return
	}
	defer func() { _ = listener.Close() }()

	slog.Info("TCP Listener started", "local", listener.Addr().String(), "remote", ltr.Remote, "port", ltr.Port)

	for {
		conn, err := listener.Accept()
		if err != nil {
			slog.Warn("Failed to accept", "err", err)
			continue
		}

		go func(netConn net.Conn) {
			defer func() { _ = netConn.Close() }()
			ts := c.connectToTransport(ltr.Protocol, ltr.Remote, ltr.Port)
			if ts.err != nil {
				slog.Error("Failed to connect to transport", "err", ts.err)
				return
			}
			c.startPipe(netConn, ts)
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

	slog.Info("UDP Listener started", "local", conn.LocalAddr().String(), "remote", ltr.Remote, "port", ltr.Port)

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
				} else if ts.gorilla != nil {
					for {
						messageType, p, err := ts.gorilla.ReadMessage()
						if err != nil {
							return
						}
						if messageType == websocket.BinaryMessage {
							_, _ = conn.WriteToUDP(p, dest)
						}
					}
				} else if ts.wt != nil {
					packetReader, ok := ts.wt.(interface {
						ReadPacket() ([]byte, error)
					})
					if !ok {
						return
					}
					for {
						packet, err := packetReader.ReadPacket()
						if err != nil {
							return
						}
						_, _ = conn.WriteToUDP(packet, dest)
					}
				} else if ts.h2 != nil {
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
		} else if ts.gorilla != nil {
			err = ts.gorilla.WriteMessage(websocket.BinaryMessage, buf[:n])
		} else if ts.wt != nil {
			_, err = ts.wt.Write(buf[:n])
		} else if ts.h2 != nil {
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
	// Stdin/Stdout are not net.Conn, so we wrap them
	rwc := &stdioReadWriteCloser{os.Stdin, os.Stdout}
	c.startPipeRWC(rwc, ts)
}

type stdioReadWriteCloser struct {
	io.Reader
	io.Writer
}

func (s *stdioReadWriteCloser) Close() error {
	return nil // Don't close stdin/stdout
}

func (c *Client) startPipeRWC(rwc io.ReadWriteCloser, ts *tunnelStream) {
	defer ts.Close()

	if ts.ws != nil {
		stop, live := tunnel.WatchWst(ts.ws, c.Config.PingFrequency, "role", "client")
		defer stop()
		tunnel.PipeRWLive(rwc, ts.ws, live)
	} else if ts.gorilla != nil {
		stop, live := tunnel.WatchGorilla(ts.gorilla, c.Config.PingFrequency, "role", "client")
		defer stop()
		tunnel.PipeGorillaRWLive(rwc, ts.gorilla, live)
	} else {
		tunnel.PipeBiDir(rwc, ts.h2)
	}
}
