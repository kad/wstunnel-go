package client

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kad/wstunnel-go/pkg/protocol"
	"github.com/kad/wstunnel-go/pkg/server"
	"github.com/kad/wstunnel-go/pkg/tun/tuntest"
)

// allowLoopbackRules admits tun sessions and TCP/UDP flows to 127.0.0.1, which
// the server's built-in deny list blocks unless a rule names it explicitly.
const allowLoopbackRules = `
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

// trackingListener remembers every accepted connection. httptest's
// CloseClientConnections forgets hijacked connections, and a websocket upgrade
// hijacks its connection, so it cannot sever a tunnel session.
type trackingListener struct {
	net.Listener
	mu    sync.Mutex
	conns []net.Conn
}

func (l *trackingListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err == nil {
		l.mu.Lock()
		l.conns = append(l.conns, c)
		l.mu.Unlock()
	}
	return c, err
}

func (l *trackingListener) closeAll() {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, c := range l.conns {
		_ = c.Close()
	}
	l.conns = nil
}

// testTunServer is an in-process tun-enabled server on a fixed address, so a
// test can stop it and start another one on the same address.
type testTunServer struct {
	addr string
	srv  *httptest.Server
	ln   *trackingListener
}

func newTestTunServer(t *testing.T, mode, addr string) *testTunServer {
	t.Helper()
	rulesPath := filepath.Join(t.TempDir(), "rules.yaml")
	if err := os.WriteFile(rulesPath, []byte(allowLoopbackRules), 0o600); err != nil {
		t.Fatal(err)
	}
	rules, err := server.LoadRestrictions(rulesPath)
	if err != nil {
		t.Fatal(err)
	}
	s := server.NewServer(server.Config{
		PathPrefix:        "v1",
		WebsocketProtocol: mode,
		EnableTun:         true,
	})
	s.SetRules(rules)

	if addr == "" {
		addr = "127.0.0.1:0"
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	tracked := &trackingListener{Listener: ln}
	srv := httptest.NewUnstartedServer(s)
	srv.Listener = tracked
	srv.Config.Protocols = new(http.Protocols)
	srv.Config.Protocols.SetHTTP1(true)
	srv.Config.Protocols.SetUnencryptedHTTP2(true)
	srv.Start()
	ts := &testTunServer{addr: ln.Addr().String(), srv: srv, ln: tracked}
	t.Cleanup(ts.stop)
	return ts
}

func (s *testTunServer) stop() {
	s.ln.closeAll()
	s.srv.Close()
}

func tcpEcho(t *testing.T) netip.AddrPort {
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

func udpEcho(t *testing.T) netip.AddrPort {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pc.Close() })
	go func() {
		buf := make([]byte, 65535)
		for {
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			_, _ = pc.WriteTo(buf[:n], addr)
		}
	}()
	return pc.LocalAddr().(*net.UDPAddr).AddrPort()
}

// startTunClient runs the client's tun loop against a fake device and returns
// the in-memory host attached to the other end of that device, plus a stop
// function that returns runTun's result.
func startTunClient(t *testing.T, cfg Config, retry tunRetry) (*tuntest.Host, func() error) {
	t.Helper()
	devEnd, hostEnd := tuntest.Pipe()
	host := tuntest.NewHost(t, hostEnd, 1500)

	c := NewClient(cfg)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- c.runTun(ctx, devEnd, 1500, retry) }()
	stop := func() error {
		cancel()
		select {
		case err := <-done:
			return err
		case <-time.After(5 * time.Second):
			t.Error("runTun did not return after cancel")
			return nil
		}
	}
	t.Cleanup(func() {
		if err := stop(); err != nil {
			t.Errorf("runTun returned %v after its context was cancelled, want nil", err)
		}
	})
	return host, stop
}

var fastRetry = tunRetry{min: 20 * time.Millisecond, max: 100 * time.Millisecond, stable: time.Second}

// attemptTimeout bounds one echo attempt. It is short because a SYN sent before
// the session is up is dropped and only retried by TCP after a full second;
// retrying sooner reaches the established session without that wait.
const attemptTimeout = 300 * time.Millisecond

// echoOnce sends msg through the tunnel and reports whether it came back.
func echoOnce(t *testing.T, host *tuntest.Host, dst netip.AddrPort, msg string) error {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), attemptTimeout)
	defer cancel()
	c, err := host.DialTCP(ctx, dst)
	if err != nil {
		return err
	}
	defer func() { _ = c.Close() }()
	_ = c.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := c.Write([]byte(msg)); err != nil {
		return err
	}
	buf := make([]byte, len(msg))
	if _, err := io.ReadFull(c, buf); err != nil {
		return err
	}
	if string(buf) != msg {
		t.Fatalf("echo = %q, want %q", buf, msg)
	}
	return nil
}

func TestRunTunForwardsTCPAndUDPOverEachTransport(t *testing.T) {
	for _, tc := range []struct {
		name, mode, scheme string
	}{
		{"rust websocket", "rust", "ws"},
		{"rfc6455 websocket", "ws", "ws"},
		{"http2", "rust", "http"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := newTestTunServer(t, tc.mode, "")
			host, _ := startTunClient(t, Config{
				ServerURL:         tc.scheme + "://" + srv.addr,
				PathPrefix:        "v1",
				WebsocketProtocol: tc.mode,
			}, fastRetry)

			tcpDst := tcpEcho(t)
			deadline := time.Now().Add(5 * time.Second)
			var err error
			for time.Now().Before(deadline) {
				// The first attempts can race the session setup.
				if err = echoOnce(t, host, tcpDst, "tcp over "+tc.name); err == nil {
					break
				}
				time.Sleep(20 * time.Millisecond)
			}
			if err != nil {
				t.Fatalf("TCP echo through the tunnel: %v", err)
			}

			udpDst := udpEcho(t)
			u, err := host.DialUDP(udpDst)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = u.Close() }()
			_ = u.SetDeadline(time.Now().Add(3 * time.Second))
			if _, err := u.Write([]byte("udp over " + tc.name)); err != nil {
				t.Fatal(err)
			}
			buf := make([]byte, 128)
			n, err := u.Read(buf)
			if err != nil || !strings.HasPrefix(string(buf[:n]), "udp over") {
				t.Fatalf("UDP echo = %q, %v", buf[:n], err)
			}
		})
	}
}

func TestRunTunReconnectsAfterServerRestart(t *testing.T) {
	srv1 := newTestTunServer(t, "rust", "")
	host, _ := startTunClient(t, Config{
		ServerURL:         "ws://" + srv1.addr,
		PathPrefix:        "v1",
		WebsocketProtocol: "rust",
	}, fastRetry)
	dst := tcpEcho(t)

	waitForEcho := func(msg string) {
		t.Helper()
		deadline := time.Now().Add(10 * time.Second)
		var err error
		for time.Now().Before(deadline) {
			if err = echoOnce(t, host, dst, msg); err == nil {
				return
			}
			time.Sleep(50 * time.Millisecond)
		}
		t.Fatalf("no echo for %q before the deadline: %v", msg, err)
	}

	waitForEcho("before restart")

	addr := srv1.addr
	srv1.stop()

	// While the server is down the device stays up and traffic is dropped, not
	// delivered anywhere else.
	if err := echoOnce(t, host, dst, "during outage"); err == nil {
		t.Fatal("traffic flowed while the server was down")
	}

	newTestTunServer(t, "rust", addr)
	waitForEcho("after restart")
}

func TestRunTunReturnsWhenDeviceFails(t *testing.T) {
	srv := newTestTunServer(t, "rust", "")
	devEnd, hostEnd := tuntest.Pipe()
	c := NewClient(Config{ServerURL: "ws://" + srv.addr, PathPrefix: "v1", WebsocketProtocol: "rust"})
	done := make(chan error, 1)
	go func() { done <- c.runTun(context.Background(), devEnd, 1500, fastRetry) }()

	time.Sleep(100 * time.Millisecond)
	_ = hostEnd.Close() // the device disappears

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("runTun returned nil after the device failed; the caller must learn the tunnel is dead")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("runTun kept running after its device failed")
	}
}

func TestRunTunExplainsServerWithoutTun(t *testing.T) {
	s := server.NewServer(server.Config{PathPrefix: "v1", WebsocketProtocol: "ws"}) // EnableTun off
	srv := httptest.NewServer(s)
	t.Cleanup(srv.Close)

	c := NewClient(Config{ServerURL: "ws://" + strings.TrimPrefix(srv.URL, "http://"), PathPrefix: "v1", WebsocketProtocol: "ws"})
	ts := c.connectToTransport(protocolTunClaim(1500), "0.0.0.0", 0)
	if ts.err == nil {
		ts.Close()
		t.Fatal("a server without --enable-tun accepted a tun session")
	}
	err := describeTunConnectError(ts)
	if !strings.Contains(err.Error(), "--enable-tun") {
		t.Fatalf("error %q should tell the operator to check --enable-tun", err)
	}
}

func TestResolveServerAddrsIPLiteral(t *testing.T) {
	c := NewClient(Config{ServerURL: "wss://203.0.113.9:8443"})
	addrs, err := c.resolveServerAddrs()
	if err != nil || len(addrs) != 1 || addrs[0] != netip.MustParseAddr("203.0.113.9") {
		t.Fatalf("resolveServerAddrs = %v, %v; want [203.0.113.9]", addrs, err)
	}
}

func protocolTunClaim(mtu uint16) protocol.LocalProtocol {
	return protocol.LocalProtocol{Tun: &protocol.TunProtocol{Mtu: mtu}}
}

func TestResolveServerAddrsFailsClosed(t *testing.T) {
	for _, u := range []string{"wss://", "ws:///x", "ws://:8080"} {
		if addrs, err := NewClient(Config{ServerURL: u}).resolveServerAddrs(); err == nil {
			t.Errorf("%q: got %v, want an error", u, addrs)
		}
	}

	orig := lookupNetIP
	t.Cleanup(func() { lookupNetIP = orig })
	lookupNetIP = func(context.Context, string) ([]netip.Addr, error) { return nil, nil }
	addrs, err := NewClient(Config{ServerURL: "wss://tun.example.test"}).resolveServerAddrs()
	if err == nil || !strings.Contains(err.Error(), "no addresses") {
		t.Fatalf("empty lookup result = %v, %v; want a no-addresses error", addrs, err)
	}

	lookupNetIP = func(context.Context, string) ([]netip.Addr, error) { return nil, errors.New("boom") }
	if _, err := NewClient(Config{ServerURL: "wss://tun.example.test"}).resolveServerAddrs(); err == nil {
		t.Fatal("lookup failure must be an error")
	}
}

func TestTunMTUErrorIsCleanInBothCases(t *testing.T) {
	rangeErr := tunMTUError("wst0", 70000, nil).Error()
	if strings.Contains(rangeErr, "nil") || !strings.Contains(rangeErr, "70000") {
		t.Errorf("range error %q should name the MTU and not print a nil error", rangeErr)
	}
	readErr := tunMTUError("wst0", 0, errors.New("no such device"))
	if !strings.Contains(readErr.Error(), "no such device") || strings.Contains(readErr.Error(), "device reports 0") {
		t.Errorf("read error %q should report the cause, not an MTU of 0", readErr)
	}
}
