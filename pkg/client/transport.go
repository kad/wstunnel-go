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

	if c.Config.SocketSoMark != 0 {
		d.Control = func(network, address string, rc syscall.RawConn) error {
			return rc.Control(func(fd uintptr) {
				_ = socket.SetSoMark(fd, c.Config.SocketSoMark)
			})
		}
	}

	conn, err := d.DialContext(ctx, network, addr)
	if err != nil {
		return nil, nil, "", err
	}

	return conn, u, host, nil
}

// dialTransport establishes a raw TCP or TLS connection to the server
func (c *Client) dialTransport(ctx context.Context, network, addr string) (net.Conn, error) {
	conn, u, host, err := c.dialRawTransport(ctx, network, addr)
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
