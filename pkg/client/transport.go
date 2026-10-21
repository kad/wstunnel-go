package client

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"syscall"
	"time"

	"github.com/kad/wstunnel-go/internal/socket"
)

// markSetter is what sets SO_MARK on a socket: socket.SetSoMark unless a test
// substituted setMark.
func (c *Client) markSetter() func(fd uintptr, mark uint32) error {
	if c.setMark != nil {
		return c.setMark
	}
	return socket.SetSoMark
}

// markControl returns the Control hook that marks the client's own sockets, nil
// when no mark is configured. In a full tunnel the mark is what keeps the
// tunnel's own traffic out of the tunnel, so a socket that cannot be marked
// fails the dial: connecting unmarked would send the tunnel's packets into the
// tunnel. Outside a full tunnel --socket-so-mark stays best effort, as it is on
// the server.
func (c *Client) markControl() func(network, address string, rc syscall.RawConn) error {
	mark := c.socketMark()
	if mark == 0 {
		return nil
	}
	strict := c.fullTunnelMark.Load() != 0
	setMark := c.markSetter()
	return func(network, address string, rc syscall.RawConn) error {
		var serr error
		if err := rc.Control(func(fd uintptr) { serr = setMark(fd, mark) }); err != nil {
			return err
		}
		if serr != nil && strict {
			return fmt.Errorf("set SO_MARK %#x on a socket of the full tunnel (refusing to connect unmarked, the tunnel's own traffic would loop into it): %w", mark, serr)
		}
		return nil
	}
}

func (c *Client) tlsClientConfig(serverName string) (*tls.Config, error) {
	tlsConfig := &tls.Config{
		InsecureSkipVerify: !c.Config.TlsVerifyCert,
		ServerName:         serverName,
	}
	if c.Config.TlsSniOverride != "" {
		tlsConfig.ServerName = c.Config.TlsSniOverride
	}
	if c.Config.TlsClientCert != "" && c.Config.TlsClientKey != "" {
		cert, err := tls.LoadX509KeyPair(c.Config.TlsClientCert, c.Config.TlsClientKey)
		if err != nil {
			return nil, fmt.Errorf("failed to load client cert: %w", err)
		}
		tlsConfig.Certificates = []tls.Certificate{cert}
	}

	return tlsConfig, nil
}

func (c *Client) dialRawTransport(ctx context.Context, network, addr string) (net.Conn, *url.URL, string, error) {
	u, err := url.Parse(c.Config.ServerURL)
	if err != nil {
		return nil, nil, "", fmt.Errorf("invalid server url: %w", err)
	}

	host := u.Hostname()
	port := u.Port()
	if port == "" {
		if u.Scheme == "wss" || u.Scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}
	// Use addr provided by dialer if possible, or fallback to Config
	if addr == "" {
		addr = net.JoinHostPort(host, port)
	}
	if network == "" {
		network = "tcp"
	}

	var d net.Dialer
	d.Timeout = 10 * time.Second

	d.Control = c.markControl()
	d.Resolver = c.resolver.Load()

	if proxyURL := c.httpProxyFor(u, addr); proxyURL != "" {
		conn, err := c.dialViaHTTPProxy(ctx, &d, network, addr, proxyURL)
		if err != nil {
			return nil, nil, "", err
		}
		return conn, u, host, nil
	}

	conn, err := c.dialPinned(ctx, &d, network, addr)
	if err != nil {
		return nil, nil, "", err
	}

	return conn, u, host, nil
}

// dialTransport establishes a raw TCP or TLS connection to the server.
//
// nextProtos, when provided, is advertised as the ALPN protocol list during the
// TLS handshake. HTTP/2 over TLS is only reachable when "h2" is negotiated via
// ALPN, so the HTTP/2 transport must ask for it explicitly.
func (c *Client) dialTransport(ctx context.Context, network, addr string, nextProtos ...string) (net.Conn, error) {
	conn, u, host, err := c.dialRawTransport(ctx, network, addr)
	if err != nil {
		return nil, err
	}

	// TLS Handshake
	if u.Scheme == "wss" || u.Scheme == "https" {
		tlsConfig, err := c.tlsClientConfig(host)
		if err != nil {
			_ = conn.Close()
			return nil, err
		}
		if len(nextProtos) > 0 {
			tlsConfig.NextProtos = nextProtos
		}

		tlsConn := tls.Client(conn, tlsConfig)

		// Wrap the TLS handshake with the same timeout as TCP connect to prevent
		// connection pool exhaustion when servers accept TCP but never complete
		// the TLS handshake (see upstream wstunnel issue #516)
		handshakeCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()

		if err := tlsConn.HandshakeContext(handshakeCtx); err != nil {
			_ = conn.Close()
			return nil, fmt.Errorf("tls handshake failed: %w", err)
		}
		return tlsConn, nil
	}

	return conn, nil
}

// dialViaHTTPProxy connects to addr through the configured HTTP proxy using CONNECT.
func (c *Client) dialViaHTTPProxy(ctx context.Context, d *net.Dialer, network, addr, proxyURL string) (net.Conn, error) {
	pu, err := url.Parse(proxyURL)
	if err != nil || pu.Host == "" {
		return nil, fmt.Errorf("invalid http proxy %q", proxyURL)
	}
	if pu.Scheme != "" && pu.Scheme != "http" {
		return nil, fmt.Errorf("unsupported http proxy scheme %q", pu.Scheme)
	}
	proxyAddr := pu.Host
	if pu.Port() == "" {
		proxyAddr = net.JoinHostPort(pu.Hostname(), "80")
	}

	conn, err := d.DialContext(ctx, network, proxyAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to http proxy: %w", err)
	}

	// Ending ctx closes the socket, which frees a CONNECT waiting for the proxy.
	stopWatch := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stopWatch()
	withReason := func(err error) error {
		if cerr := ctx.Err(); cerr != nil && !errors.Is(err, cerr) {
			return fmt.Errorf("%w: %w", cerr, err)
		}
		return err
	}

	user, pass := c.Config.HttpProxyLogin, c.Config.HttpProxyPassword
	if user == "" && pu.User != nil {
		user = pu.User.Username()
		pass, _ = pu.User.Password()
	}

	req := &http.Request{
		Method: http.MethodConnect,
		URL:    &url.URL{Opaque: addr},
		Host:   addr,
		Header: make(http.Header),
	}
	if user != "" || pass != "" {
		req.Header.Set("Proxy-Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(user+":"+pass)))
	}

	deadline := time.Now().Add(10 * time.Second)
	if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
		deadline = dl
	}
	_ = conn.SetDeadline(deadline)
	if err := req.Write(conn); err != nil {
		_ = conn.Close()
		return nil, withReason(fmt.Errorf("http proxy CONNECT write failed: %w", err))
	}
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, req)
	if err != nil {
		_ = conn.Close()
		return nil, withReason(fmt.Errorf("http proxy CONNECT failed: %w", err))
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		_ = conn.Close()
		return nil, fmt.Errorf("http proxy CONNECT to %s refused: %s", addr, resp.Status)
	}
	_ = conn.SetDeadline(time.Time{})

	if br.Buffered() > 0 {
		return &bufferedConn{Conn: conn, r: br}, nil
	}
	return conn, nil
}

type bufferedConn struct {
	net.Conn
	r *bufio.Reader
}

func (b *bufferedConn) Read(p []byte) (int, error) { return b.r.Read(p) }

// httpProxyFor returns the proxy to reach the server: the configured one, else
// the HTTP(S)_PROXY / NO_PROXY environment.
func (c *Client) httpProxyFor(u *url.URL, addr string) string {
	if c.Config.HttpProxy != "" {
		return c.Config.HttpProxy
	}
	scheme := "http"
	if u.Scheme == "wss" || u.Scheme == "https" {
		scheme = "https"
	}
	pu, err := http.ProxyFromEnvironment(&http.Request{URL: &url.URL{Scheme: scheme, Host: addr}})
	if err != nil || pu == nil {
		return ""
	}
	return pu.String()
}
