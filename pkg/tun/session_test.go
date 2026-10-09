package tun_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kad/wstunnel-go/pkg/tun"
	"github.com/kad/wstunnel-go/pkg/tun/tuntest"
)

func allowAll(tun.Flow) bool { return true }

// startSession runs Serve on one end of an in-memory pipe and returns a client
// host attached to the other end, plus Serve's result channel.
func startSession(t *testing.T, opts tun.Options) (*tuntest.Host, <-chan error) {
	t.Helper()
	serverEnd, clientEnd := tuntest.Pipe()
	return startSessionOn(t, serverEnd, clientEnd, opts)
}

func startSessionOn(t *testing.T, serverEnd, clientEnd tun.PacketConn, opts tun.Options) (*tuntest.Host, <-chan error) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- tun.Serve(ctx, serverEnd, opts)
		// Closing lets both the test and the cleanup below observe completion.
		close(done)
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("Serve did not return after cancel")
		}
	})
	mtu := opts.MTU
	if mtu == 0 {
		mtu = tun.DefaultMTU
	}
	return tuntest.NewHost(t, clientEnd, mtu), done
}

func tcpEchoServer(t *testing.T) netip.AddrPort {
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

func udpEchoServer(t *testing.T) netip.AddrPort {
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

func dialTCP(t *testing.T, h *tuntest.Host, dst netip.AddrPort) net.Conn {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, err := h.DialTCP(ctx, dst)
	if err != nil {
		t.Fatalf("DialTCP(%s): %v", dst, err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func TestServeForwardsTCP(t *testing.T) {
	h, _ := startSession(t, tun.Options{Authorize: allowAll})
	c := dialTCP(t, h, tcpEchoServer(t))

	// Larger than a window's worth, so the transfer needs many segments.
	want := bytes.Repeat([]byte("wstunnel-tun-"), 20000)
	go func() { _, _ = c.Write(want) }()
	got := make([]byte, len(want))
	_ = c.SetReadDeadline(time.Now().Add(10 * time.Second))
	if _, err := io.ReadFull(c, got); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("echoed data differs")
	}
}

func TestServeForwardsUDP(t *testing.T) {
	h, _ := startSession(t, tun.Options{Authorize: allowAll})
	c, err := h.DialUDP(udpEchoServer(t))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()

	for _, msg := range []string{"one", "two", "three"} {
		if _, err := c.Write([]byte(msg)); err != nil {
			t.Fatal(err)
		}
		buf := make([]byte, 64)
		_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
		n, err := c.Read(buf)
		if err != nil {
			t.Fatalf("read %q: %v", msg, err)
		}
		if string(buf[:n]) != msg {
			t.Fatalf("echo = %q, want %q", buf[:n], msg)
		}
	}
}

func TestServeDeniedTCPFlowIsRefusedFast(t *testing.T) {
	var seen atomic.Value
	h, _ := startSession(t, tun.Options{Authorize: func(f tun.Flow) bool {
		seen.Store(f)
		return false
	}})
	dst := tcpEchoServer(t)

	start := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err := h.DialTCP(ctx, dst)
	if err == nil || !strings.Contains(err.Error(), "refused") {
		t.Fatalf("DialTCP error = %v, want connection refused", err)
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("refusal took %v, want < 1s", elapsed)
	}
	f, _ := seen.Load().(tun.Flow)
	if f.Network != "tcp" || f.Dst != dst || f.Src.Addr() != tuntest.Addr4 {
		t.Fatalf("Authorize saw %+v, want tcp %s from %s", f, dst, tuntest.Addr4)
	}
}

func TestServeFailedDialIsRefused(t *testing.T) {
	h, _ := startSession(t, tun.Options{
		Authorize: allowAll,
		Dial: func(context.Context, string, string) (net.Conn, error) {
			return nil, errors.New("boom")
		},
	})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := h.DialTCP(ctx, netip.MustParseAddrPort("192.0.2.1:80")); err == nil || !strings.Contains(err.Error(), "refused") {
		t.Fatalf("DialTCP error = %v, want connection refused", err)
	}
}

func TestServeEnforcesMaxFlows(t *testing.T) {
	h, _ := startSession(t, tun.Options{Authorize: allowAll, MaxFlows: 1})
	dst := tcpEchoServer(t)
	first := dialTCP(t, h, dst)
	if _, err := first.Write([]byte("x")); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := h.DialTCP(ctx, dst); err == nil {
		t.Fatal("second flow succeeded with MaxFlows=1")
	}
}

// trackingDial records every outbound connection so tests can observe when
// the session closes them.
type trackingDial struct {
	mu    sync.Mutex
	conns []*trackedConn
}

type trackedConn struct {
	net.Conn
	closed chan struct{}
	once   sync.Once
}

func (c *trackedConn) Close() error {
	c.once.Do(func() { close(c.closed) })
	return c.Conn.Close()
}

func (d *trackingDial) Dial(ctx context.Context, network, addr string) (net.Conn, error) {
	var nd net.Dialer
	c, err := nd.DialContext(ctx, network, addr)
	if err != nil {
		return nil, err
	}
	tc := &trackedConn{Conn: c, closed: make(chan struct{})}
	d.mu.Lock()
	d.conns = append(d.conns, tc)
	d.mu.Unlock()
	return tc, nil
}

func (d *trackingDial) only(t *testing.T) *trackedConn {
	t.Helper()
	d.mu.Lock()
	defer d.mu.Unlock()
	if len(d.conns) != 1 {
		t.Fatalf("dialed %d connections, want 1", len(d.conns))
	}
	return d.conns[0]
}

func waitClosed(t *testing.T, c *trackedConn, within time.Duration) {
	t.Helper()
	select {
	case <-c.closed:
	case <-time.After(within):
		t.Fatalf("outbound connection still open after %v", within)
	}
}

func TestServeUDPIdleTimeoutClosesFlow(t *testing.T) {
	var d trackingDial
	h, _ := startSession(t, tun.Options{Authorize: allowAll, Dial: d.Dial, UDPIdleTimeout: 200 * time.Millisecond})
	c, err := h.DialUDP(udpEchoServer(t))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	if _, err := c.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 16)
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := c.Read(buf); err != nil {
		t.Fatal(err)
	}
	waitClosed(t, d.only(t), 2*time.Second)
}

func TestServeCloseAbortsFlows(t *testing.T) {
	var d trackingDial
	serverEnd, clientEnd := tuntest.Pipe()
	h, done := startSessionOn(t, serverEnd, clientEnd, tun.Options{Authorize: allowAll, Dial: d.Dial})
	c := dialTCP(t, h, tcpEchoServer(t))
	if _, err := c.Write([]byte("x")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 1)
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := c.Read(buf); err != nil {
		t.Fatal(err)
	}

	_ = clientEnd.Close() // the tunnel transport drops
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Serve returned %v after peer disconnect, want nil", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Serve did not return after peer disconnect")
	}
	waitClosed(t, d.only(t), 2*time.Second)
}

// maxSizeConn records the largest packet written through it.
type maxSizeConn struct {
	tun.PacketConn
	max atomic.Int64
}

func (m *maxSizeConn) WritePacket(p []byte) error {
	if n := int64(len(p)); n > m.max.Load() {
		m.max.Store(n)
	}
	return m.PacketConn.WritePacket(p)
}

func TestServeRespectsMTU(t *testing.T) {
	const mtu = 1280
	serverEnd, clientEnd := tuntest.Pipe()
	rec := &maxSizeConn{PacketConn: serverEnd}
	h, _ := startSessionOn(t, rec, clientEnd, tun.Options{Authorize: allowAll, MTU: mtu})
	c := dialTCP(t, h, tcpEchoServer(t))

	want := bytes.Repeat([]byte{0xAB}, 64*1024)
	go func() { _, _ = c.Write(want) }()
	_ = c.SetReadDeadline(time.Now().Add(10 * time.Second))
	if _, err := io.ReadFull(c, make([]byte, len(want))); err != nil {
		t.Fatal(err)
	}
	if got := rec.max.Load(); got > mtu {
		t.Fatalf("server sent a %d-byte packet, MTU is %d", got, mtu)
	}
}

func TestServeRejectsInvalidOptions(t *testing.T) {
	for name, opts := range map[string]tun.Options{
		"no authorize": {},
		"mtu too low":  {Authorize: allowAll, MTU: 576},
	} {
		t.Run(name, func(t *testing.T) {
			a, b := tuntest.Pipe()
			defer func() { _ = b.Close() }()
			if err := tun.Serve(context.Background(), a, opts); err == nil {
				t.Fatal("Serve accepted invalid options")
			}
		})
	}
}

func TestServeForwardsTCPOverIPv6(t *testing.T) {
	ln, err := net.Listen("tcp", "[::1]:0")
	if err != nil {
		t.Skipf("IPv6 loopback unavailable: %v", err)
	}
	defer func() { _ = ln.Close() }()
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		_, _ = io.Copy(c, c)
		_ = c.Close()
	}()

	var seen atomic.Value
	h, _ := startSession(t, tun.Options{Authorize: func(f tun.Flow) bool {
		seen.Store(f)
		return true
	}})
	c := dialTCP(t, h, ln.Addr().(*net.TCPAddr).AddrPort())
	if _, err := c.Write([]byte("v6")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 2)
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.ReadFull(c, buf); err != nil || string(buf) != "v6" {
		t.Fatalf("echo = %q, %v", buf, err)
	}
	if f := seen.Load().(tun.Flow); f.Src.Addr() != tuntest.Addr6 {
		t.Fatalf("flow source = %s, want %s", f.Src.Addr(), tuntest.Addr6)
	}
}
