package client

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/url"
	"syscall"
	"time"

	"github.com/kad/wstunnel-go/internal/socket"
)

// dialTransport establishes a raw TCP or TLS connection to the server
func (c *Client) dialTransport(ctx context.Context) (net.Conn, error) {
	u, err := url.Parse(c.Config.ServerURL)
	if err != nil {
		return nil, fmt.Errorf("invalid server url: %w", err)
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
	addr := net.JoinHostPort(host, port)

	var d net.Dialer
	d.Timeout = 10 * time.Second

	if c.Config.SocketSoMark != 0 {
		d.Control = func(network, address string, rc syscall.RawConn) error {
			return rc.Control(func(fd uintptr) {
				_ = socket.SetSoMark(fd, c.Config.SocketSoMark)
			})
		}
	}

	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}

	// TLS Handshake
	if u.Scheme == "wss" || u.Scheme == "https" {
		tlsConfig := &tls.Config{
			InsecureSkipVerify: !c.Config.TlsVerifyCert,
			ServerName:         host,
		}
		if c.Config.TlsSniOverride != "" {
			tlsConfig.ServerName = c.Config.TlsSniOverride
		}
		if c.Config.TlsClientCert != "" && c.Config.TlsClientKey != "" {
			cert, err := tls.LoadX509KeyPair(c.Config.TlsClientCert, c.Config.TlsClientKey)
			if err != nil {
				_ = conn.Close()
				return nil, fmt.Errorf("failed to load client cert: %w", err)
			}
			tlsConfig.Certificates = []tls.Certificate{cert}
		}

		tlsConn := tls.Client(conn, tlsConfig)
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			_ = conn.Close()
			return nil, fmt.Errorf("tls handshake failed: %w", err)
		}
		return tlsConn, nil
	}

	return conn, nil
}
