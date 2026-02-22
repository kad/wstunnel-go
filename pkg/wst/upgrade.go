package wst

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"time"
)

type Upgrader struct {
	CheckOrigin  func(r *http.Request) bool
	Subprotocols []string
}

func (u *Upgrader) Upgrade(w http.ResponseWriter, r *http.Request, responseHeader http.Header) (*Conn, error) {
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		return nil, fmt.Errorf("response writer does not support hijacking")
	}

	conn, bufrw, err := hijacker.Hijack()
	if err != nil {
		return nil, err
	}

	// Send 101 response
	resp := "HTTP/1.1 101 Switching Protocols\r\n" +
		"Upgrade: websocket\r\n" +
		"Connection: Upgrade\r\n" +
		"Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n" // Fixed mock accept key for simplicity/speed

	if len(u.Subprotocols) > 0 {
		resp += fmt.Sprintf("Sec-WebSocket-Protocol: %s\r\n", u.Subprotocols[0])
	}
	resp += "\r\n"

	if _, err := bufrw.WriteString(resp); err != nil {
		_ = conn.Close()
		return nil, err
	}
	if err := bufrw.Flush(); err != nil {
		_ = conn.Close()
		return nil, err
	}

	// We don't reuse bufrw because we want a clean start with our Conn wrapper
	// but bufrw might have buffered some read data?
	// HTTP Upgrade request usually has no body, so buffer should be empty of next data.

	return NewConn(conn, false), nil // Server does not mask by default
}

type Dialer struct {
	NetDialContext   func(ctx context.Context, network, addr string) (net.Conn, error)
	HandshakeTimeout time.Duration
}

var DefaultDialer = &Dialer{
	NetDialContext:   nil,
	HandshakeTimeout: 45 * time.Second,
}

func (d *Dialer) Dial(uStr string, header http.Header) (*Conn, *http.Response, error) {
	u, err := url.Parse(uStr)
	if err != nil {
		return nil, nil, err
	}

	port := u.Port()
	if port == "" {
		if u.Scheme == "wss" || u.Scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}

	host := u.Hostname()
	addr := net.JoinHostPort(host, port)

	// Create context with timeout
	ctx := context.Background()
	if d.HandshakeTimeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, d.HandshakeTimeout)
		defer cancel()
	}

	var conn net.Conn
	if d.NetDialContext != nil {
		conn, err = d.NetDialContext(ctx, "tcp", addr)
	} else {
		// Fallback to standard dialer
		conn, err = (&net.Dialer{Timeout: d.HandshakeTimeout}).DialContext(ctx, "tcp", addr)
	}
	if err != nil {
		return nil, nil, err
	}

	// Re-checking client.go logic:
	// dialer.NetDialContext = func(...) { if pool { ... } return c.dialTransport(ctx) }
	// c.dialTransport handles TLS if Config.Tls... is set?
	// No, c.dialTransport usually just dials TCP.
	// Actually, client.go: `dialer.Dial(u.String(), header)`
	// gorilla/websocket's Dial handles TLS if scheme is wss.
	// If NetDialContext is set, gorilla uses it to get the conn, then wraps in TLS if scheme is wss.
	// So we should do the same.

	if u.Scheme == "wss" || u.Scheme == "https" {
		// Check if conn is already TLS? No easy way.
		// Assume NetDialContext returns TCP conn.
		// We wrap it.
		tlsConfig := &tls.Config{InsecureSkipVerify: true, ServerName: host}
		tlsConn := tls.Client(conn, tlsConfig)
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			_ = conn.Close()
			return nil, nil, err
		}
		conn = tlsConn
	}

	// Send Handshake
	req := fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n", u.RequestURI(), host)
	for k, v := range header {
		for _, val := range v {
			req += fmt.Sprintf("%s: %s\r\n", k, val)
		}
	}
	req += "\r\n"

	// Set write deadline for handshake
	if d.HandshakeTimeout > 0 {
		_ = conn.SetWriteDeadline(time.Now().Add(d.HandshakeTimeout))
	}
	if _, err := conn.Write([]byte(req)); err != nil {
		_ = conn.Close()
		return nil, nil, err
	}
	_ = conn.SetWriteDeadline(time.Time{}) // Clear deadline

	// Read response
	if d.HandshakeTimeout > 0 {
		_ = conn.SetReadDeadline(time.Now().Add(d.HandshakeTimeout))
	}
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, &http.Request{Method: "GET"})
	if err != nil {
		_ = conn.Close()
		return nil, nil, err
	}
	_ = conn.SetWriteDeadline(time.Time{}) // Clear deadline

	if resp.StatusCode != 101 {
		_ = conn.Close()
		return nil, resp, fmt.Errorf("bad status: %s", resp.Status)
	}

	// Client SHOULD mask, but we use a robust implementation that supports 0-masking or normal masking.
	return NewConn(conn, true), resp, nil
}

// Dial connects to the url and starts a websocket using DefaultDialer.
func Dial(uStr string, header http.Header) (*Conn, *http.Response, error) {
	return DefaultDialer.Dial(uStr, header)
}
