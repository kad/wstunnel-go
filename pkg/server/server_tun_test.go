package server

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/gorilla/websocket"
	"github.com/kad/wstunnel-go/pkg/protocol"
	"github.com/kad/wstunnel-go/pkg/tun"
	"github.com/kad/wstunnel-go/pkg/tun/tuntest"
	"github.com/kad/wstunnel-go/pkg/wst"
)

// tunLoopbackRules admits tun sessions and TCP/UDP flows to 127.0.0.1, which
// the built-in deny list blocks unless a rule names it explicitly.
const tunLoopbackRules = `
restrictions:
  - name: tun-loopback
    match:
      - Any
    allow:
      - !Tunnel
        protocol: [Tun]
      - !Tunnel
        protocol: [Tcp, Udp]
        cidr: [127.0.0.1/32]
`

func tunToken(t *testing.T, mtu uint16) string {
	t.Helper()
	claims := protocol.JwtTunnelConfig{
		ID:       "tun-test",
		Protocol: protocol.LocalProtocol{Tun: &protocol.TunProtocol{Mtu: mtu}},
		Remote:   "0.0.0.0",
	}
	token, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte("test-secret"))
	if err != nil {
		t.Fatal(err)
	}
	return token
}

// startTunServer serves s over cleartext HTTP/1.1 and h2c.
func startTunServer(t *testing.T, s *Server) string {
	t.Helper()
	srv := httptest.NewUnstartedServer(s.mux)
	srv.Config.Protocols = new(http.Protocols)
	srv.Config.Protocols.SetHTTP1(true)
	srv.Config.Protocols.SetUnencryptedHTTP2(true)
	srv.Start()
	t.Cleanup(srv.Close)
	return strings.TrimPrefix(srv.URL, "http://")
}

type tunDialer func(t *testing.T, addr, token string) (tun.PacketConn, error)

func dialTunWST(t *testing.T, addr, token string) (tun.PacketConn, error) {
	h := http.Header{"Sec-WebSocket-Protocol": {"v1, " + protocol.JwtHeaderPrefix + token}}
	c, resp, err := (&wst.Dialer{HandshakeTimeout: 5 * time.Second}).Dial("ws://"+addr+"/v1/events", h)
	if err != nil {
		if resp != nil {
			return nil, &statusError{resp.StatusCode}
		}
		return nil, err
	}
	return tun.NewWSTPacketConn(c), nil
}

func dialTunGorilla(t *testing.T, addr, token string) (tun.PacketConn, error) {
	d := websocket.Dialer{
		HandshakeTimeout: 5 * time.Second,
		Subprotocols:     []string{"v1", protocol.JwtHeaderPrefix + token},
	}
	c, resp, err := d.Dial("ws://"+addr+"/v1/events", nil)
	if err != nil {
		if resp != nil {
			return nil, &statusError{resp.StatusCode}
		}
		return nil, err
	}
	return tun.NewGorillaPacketConn(c), nil
}

func dialTunH2(t *testing.T, addr, token string) (tun.PacketConn, error) {
	// Prior-knowledge h2c, as the client uses for http:// server URLs.
	protocols := new(http.Protocols)
	protocols.SetUnencryptedHTTP2(true)
	tr := &http.Transport{Protocols: protocols}
	t.Cleanup(tr.CloseIdleConnections)
	pr, pw := io.Pipe()
	req, err := http.NewRequest(http.MethodPost, "http://"+addr+"/v1/events", pr)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Cookie", token)
	resp, err := tr.RoundTrip(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		_ = resp.Body.Close()
		return nil, &statusError{resp.StatusCode}
	}
	return tun.NewFramedPacketConn(&h2Stream{body: resp.Body, w: pw}), nil
}

type h2Stream struct {
	body io.ReadCloser
	w    *io.PipeWriter
}

func (s *h2Stream) Read(p []byte) (int, error)  { return s.body.Read(p) }
func (s *h2Stream) Write(p []byte) (int, error) { return s.w.Write(p) }
func (s *h2Stream) Close() error {
	_ = s.w.Close()
	return s.body.Close()
}

type statusError struct{ code int }

func (e *statusError) Error() string { return http.StatusText(e.code) }

var tunTransports = []struct {
	name string
	mode string // Config.WebsocketProtocol
	dial tunDialer
}{
	{"rust", "rust", dialTunWST},
	{"gorilla", "ws", dialTunGorilla},
	{"h2", "rust", dialTunH2},
}

func echoListener(t *testing.T) netip.AddrPort {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				_, _ = io.Copy(c, c)
				_ = c.Close()
			}()
		}
	}()
	return ln.Addr().(*net.TCPAddr).AddrPort()
}

func TestTunSessionAcrossTransports(t *testing.T) {
	for _, tr := range tunTransports {
		t.Run(tr.name, func(t *testing.T) {
			s := NewServer(Config{WebsocketProtocol: tr.mode, EnableTun: true})
			s.SetRules(tunRules(t, tunLoopbackRules))
			addr := startTunServer(t, s)

			pc, err := tr.dial(t, addr, tunToken(t, 1500))
			if err != nil {
				t.Fatalf("dial: %v", err)
			}
			host := tuntest.NewHost(t, pc, 1500)

			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			c, err := host.DialTCP(ctx, echoListener(t))
			if err != nil {
				t.Fatalf("DialTCP through %s: %v", tr.name, err)
			}
			defer func() { _ = c.Close() }()
			if _, err := c.Write([]byte("over-" + tr.name)); err != nil {
				t.Fatal(err)
			}
			buf := make([]byte, len("over-"+tr.name))
			_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
			if _, err := io.ReadFull(c, buf); err != nil || string(buf) != "over-"+tr.name {
				t.Fatalf("echo = %q, %v", buf, err)
			}
		})
	}
}

func TestTunSessionRejectedWhenDisabled(t *testing.T) {
	// An empty protocol list admits every protocol, so only EnableTun stands
	// between this rule and a tun session.
	permissive := `
restrictions:
  - name: everything
    match:
      - Any
    allow:
      - !Tunnel {}
`
	for _, tr := range tunTransports {
		t.Run(tr.name, func(t *testing.T) {
			s := NewServer(Config{WebsocketProtocol: tr.mode})
			s.SetRules(tunRules(t, permissive))
			addr := startTunServer(t, s)

			_, err := tr.dial(t, addr, tunToken(t, 1500))
			var se *statusError
			if !errors.As(err, &se) || se.code != http.StatusForbidden {
				t.Fatalf("dial error = %v, want 403 Forbidden", err)
			}
		})
	}
}

func TestTunSessionDeniesLoopbackByDefault(t *testing.T) {
	s := NewServer(Config{EnableTun: true}) // no restrictions configured
	addr := startTunServer(t, s)
	pc, err := dialTunWST(t, addr, tunToken(t, 1500))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	host := tuntest.NewHost(t, pc, 1500)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := host.DialTCP(ctx, echoListener(t)); err == nil || !strings.Contains(err.Error(), "refused") {
		t.Fatalf("DialTCP to server loopback = %v, want connection refused", err)
	}
}
