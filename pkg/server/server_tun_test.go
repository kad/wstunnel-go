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
	return tunTokenFor(t, mtu, "0.0.0.0", 0)
}

// tunTokenFor signs a tun claim with an arbitrary (possibly forged) r and rp.
func tunTokenFor(t *testing.T, mtu uint16, remote string, port uint16) string {
	t.Helper()
	claims := protocol.JwtTunnelConfig{
		ID:       "tun-test",
		Protocol: protocol.LocalProtocol{Tun: &protocol.TunProtocol{Mtu: mtu}},
		Remote:   remote,
		Port:     port,
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

// streamingUDPServer replies to every datagram it receives with a continuous
// stream of datagrams until the test ends.
func streamingUDPServer(t *testing.T) netip.AddrPort {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	t.Cleanup(func() { close(done); _ = pc.Close() })
	go func() {
		buf := make([]byte, 64)
		for {
			_, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			go func() {
				payload := make([]byte, 1000)
				for {
					select {
					case <-done:
						return
					default:
					}
					if _, err := pc.WriteTo(payload, from); err != nil {
						return
					}
					time.Sleep(50 * time.Microsecond)
				}
			}()
		}
	}()
	return pc.LocalAddr().(*net.UDPAddr).AddrPort()
}

// TestTunH2HalfCloseDoesNotCrashServer: the client ends its request body while
// the server is still streaming to it. Serve must not return (and so the
// handler must not finish) while a pump can still write to the ResponseWriter,
// or net/http panics with "Write called after Handler finished".
func TestTunH2HalfCloseDoesNotCrashServer(t *testing.T) {
	s := NewServer(Config{WebsocketProtocol: "rust", EnableTun: true})
	s.SetRules(tunRules(t, tunLoopbackRules))
	addr := startTunServer(t, s)
	udpAddr := streamingUDPServer(t)

	protocols := new(http.Protocols)
	protocols.SetUnencryptedHTTP2(true)
	tr := &http.Transport{Protocols: protocols}
	t.Cleanup(tr.CloseIdleConnections)

	for i := 0; i < 25; i++ {
		pr, pw := io.Pipe()
		req, err := http.NewRequest(http.MethodPost, "http://"+addr+"/v1/events", pr)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Cookie", tunToken(t, 1500))
		resp, err := tr.RoundTrip(req)
		if err != nil {
			t.Fatal(err)
		}
		pc := tun.NewFramedPacketConn(&h2Stream{body: resp.Body, w: pw})
		host := tuntest.NewHost(t, pc, 1500)

		c, err := host.DialUDP(udpAddr)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := c.Write([]byte("go")); err != nil {
			t.Fatal(err)
		}
		_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
		if _, err := c.Read(make([]byte, 2000)); err != nil {
			t.Fatalf("no streamed datagram: %v", err)
		}
		time.Sleep(5 * time.Millisecond) // let the server queue more output
		_ = pw.Close()                   // half-close: END_STREAM on the request body

		// The server must end the response; keep draining so it is not just
		// blocked on flow control.
		drained := make(chan struct{})
		go func() { _, _ = io.Copy(io.Discard, resp.Body); close(drained) }()
		select {
		case <-drained:
		case <-time.After(10 * time.Second):
			t.Fatal("server did not end the response after half-close")
		}
		_ = c.Close()
	}
}

func TestTunMaxFlowsIsSharedAcrossSessions(t *testing.T) {
	s := NewServer(Config{WebsocketProtocol: "rust", EnableTun: true, TunMaxFlows: 2})
	s.SetRules(tunRules(t, tunLoopbackRules))
	addr := startTunServer(t, s)
	echo := echoListener(t)

	newHost := func() *tuntest.Host {
		pc, err := dialTunWST(t, addr, tunToken(t, 1500))
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		return tuntest.NewHost(t, pc, 1500)
	}
	a, b := newHost(), newHost()
	dial := func(h *tuntest.Host) (net.Conn, error) {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return h.DialTCP(ctx, echo)
	}

	c1, err := dial(a)
	if err != nil {
		t.Fatalf("flow 1: %v", err)
	}
	c2, err := dial(b)
	if err != nil {
		t.Fatalf("flow 2: %v", err)
	}
	defer func() { _ = c2.Close() }()
	if c3, err := dial(a); err == nil {
		_ = c3.Close()
		t.Fatal("third flow was admitted past tun_max_flows=2")
	}

	_ = c1.Close()
	deadline := time.Now().Add(5 * time.Second)
	for {
		c4, err := dial(b)
		if err == nil {
			_ = c4.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("slot not freed after closing a flow: %v", err)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func TestTunMaxSessionsRefusesExtraSessions(t *testing.T) {
	s := NewServer(Config{WebsocketProtocol: "rust", EnableTun: true, TunMaxSessions: 1})
	s.SetRules(tunRules(t, tunLoopbackRules))
	addr := startTunServer(t, s)

	first, err := dialTunWST(t, addr, tunToken(t, 1500))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = first.Close() }()
	host := tuntest.NewHost(t, first, 1500)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, err := host.DialTCP(ctx, echoListener(t)) // ensures session 1 is registered
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()

	second, err := dialTunWST(t, addr, tunToken(t, 1500))
	if err != nil {
		t.Fatalf("upgrade should still succeed: %v", err)
	}
	read := make(chan error, 1)
	go func() { _, err := second.ReadPacket(); read <- err }()
	select {
	case err := <-read:
		if err == nil {
			t.Fatal("read data from a refused session")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("second session was not closed")
	}

	// Closing the first session frees its slot.
	_ = first.Close()
	deadline := time.Now().Add(5 * time.Second)
	for {
		third, err := dialTunWST(t, addr, tunToken(t, 1500))
		if err != nil {
			t.Fatal(err)
		}
		h := tuntest.NewHost(t, third, 1500)
		cctx, ccancel := context.WithTimeout(context.Background(), 2*time.Second)
		c3, err := h.DialTCP(cctx, echoListener(t))
		ccancel()
		if err == nil {
			_ = c3.Close()
			return
		}
		_ = third.Close()
		if time.Now().After(deadline) {
			t.Fatalf("session slot not freed: %v", err)
		}
	}
}

func TestTunForgedDestinationClaimDoesNotAdmit(t *testing.T) {
	s := NewServer(Config{WebsocketProtocol: "rust", EnableTun: true})
	s.SetRules(tunRules(t, `
restrictions:
  - name: host-port-only
    match: [Any]
    allow:
      - !Tunnel
        cidr: [10.0.0.1/32]
        port: ["22"]
`))
	addr := startTunServer(t, s)
	for _, tok := range []string{tunTokenFor(t, 1500, "0.0.0.0", 0), tunTokenFor(t, 1500, "10.0.0.1", 22)} {
		_, err := dialTunWST(t, addr, tok)
		var se *statusError
		if !errors.As(err, &se) || se.code != http.StatusForbidden {
			t.Fatalf("dial error = %v, want 403", err)
		}
	}
}

// TestH2ForwardTunnelEndsCleanly: a forward h2 tunnel whose target sends data
// and closes must end the response with END_STREAM, not RST_STREAM.
func TestH2ForwardTunnelEndsCleanly(t *testing.T) {
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
				_, _ = c.Write(make([]byte, 100_000))
				_ = c.Close()
			}()
		}
	}()
	target := ln.Addr().(*net.TCPAddr)

	s := NewServer(Config{WebsocketProtocol: "rust"})
	addr := startTunServer(t, s)
	claims := protocol.JwtTunnelConfig{
		ID:       "fwd",
		Protocol: protocol.LocalProtocol{Tcp: &protocol.TcpProtocol{}},
		Remote:   "127.0.0.1",
		Port:     uint16(target.Port),
	}
	token, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte("test-secret"))
	if err != nil {
		t.Fatal(err)
	}

	protocols := new(http.Protocols)
	protocols.SetUnencryptedHTTP2(true)
	tr := &http.Transport{Protocols: protocols}
	t.Cleanup(tr.CloseIdleConnections)

	bad := 0
	const iterations = 50
	for i := 0; i < iterations; i++ {
		pr, pw := io.Pipe()
		req, err := http.NewRequest(http.MethodPost, "http://"+addr+"/v1/events", pr)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Cookie", token)
		resp, err := tr.RoundTrip(req)
		if err != nil {
			t.Fatal(err)
		}
		n, err := io.Copy(io.Discard, resp.Body)
		if err != nil || n != 100_000 {
			bad++
			t.Logf("iteration %d: read %d bytes, err = %v", i, n, err)
		}
		_ = pw.Close()
		_ = resp.Body.Close()
	}
	if bad != 0 {
		t.Fatalf("%d/%d forward h2 tunnels did not end cleanly", bad, iterations)
	}
}

func TestTunAllowLimitsFlowsEndToEnd(t *testing.T) {
	for _, tc := range []struct {
		name    string
		allow   []string
		allowed bool
	}{
		{"destination listed", []string{"127.0.0.1/32"}, true},
		{"destination not listed", []string{"10.0.0.0/8"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := NewServer(Config{EnableTun: true, TunAllow: tc.allow})
			s.SetRules(tunRules(t, tunLoopbackRules))
			addr := startTunServer(t, s)
			pc, err := dialTunWST(t, addr, tunToken(t, 1500))
			if err != nil {
				t.Fatalf("dial: %v", err)
			}
			host := tuntest.NewHost(t, pc, 1500)

			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			c, err := host.DialTCP(ctx, echoListener(t))
			if tc.allowed {
				if err != nil {
					t.Fatalf("a flow inside tun_allow was refused: %v", err)
				}
				_ = c.Close()
				return
			}
			if err == nil {
				_ = c.Close()
				t.Fatal("a flow outside tun_allow was accepted")
			}
		})
	}
}
