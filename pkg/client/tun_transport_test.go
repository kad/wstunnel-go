package client

import (
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kad/wstunnel-go/pkg/tun/tuntest"
)

// freezeProxy forwards TCP to target. freeze() silently stops forwarding on the
// connections that exist at that moment (nothing is closed, no RST or FIN), the
// way a dead path behaves; connections made afterwards work normally.
type freezeProxy struct {
	ln       net.Listener
	accepted atomic.Int32
	mu       sync.Mutex
	frozen   map[net.Conn]chan struct{}
}

func newFreezeProxy(t *testing.T, target string) *freezeProxy {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p := &freezeProxy{ln: ln, frozen: map[net.Conn]chan struct{}{}}
	var wg sync.WaitGroup
	t.Cleanup(func() {
		_ = ln.Close()
		p.mu.Lock()
		for c, ch := range p.frozen {
			_ = c.Close()
			select {
			case <-ch:
			default:
				close(ch)
			}
		}
		p.mu.Unlock()
		wg.Wait()
	})
	wg.Go(func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			p.accepted.Add(1)
			up, err := net.Dial("tcp", target)
			if err != nil {
				_ = c.Close()
				continue
			}
			stop := make(chan struct{})
			p.mu.Lock()
			p.frozen[c] = stop
			p.mu.Unlock()
			pipe := func(dst, src net.Conn) {
				buf := make([]byte, 32<<10)
				for {
					n, err := src.Read(buf)
					if n > 0 {
						select {
						case <-stop:
							// Frozen: swallow the bytes.
						default:
							if _, werr := dst.Write(buf[:n]); werr != nil {
								return
							}
						}
					}
					if err != nil {
						return
					}
				}
			}
			wg.Go(func() { pipe(up, c); _ = up.Close(); _ = c.Close() })
			wg.Go(func() { pipe(c, up); _ = up.Close(); _ = c.Close() })
		}
	})
	return p
}

func (p *freezeProxy) addr() string { return p.ln.Addr().String() }

// freeze makes every existing connection swallow its traffic from now on.
func (p *freezeProxy) freeze() {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, ch := range p.frozen {
		select {
		case <-ch:
		default:
			close(ch)
		}
	}
}

func waitEcho(t *testing.T, host *tuntest.Host, msg string) {
	t.Helper()
	dst := tcpEcho(t)
	deadline := time.Now().Add(10 * time.Second)
	var err error
	for time.Now().Before(deadline) {
		if err = echoOnce(t, host, dst, msg); err == nil {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("no echo for %q: %v", msg, err)
}

func TestRunTunHTTP2DropsSilentPeer(t *testing.T) {
	srv := newTestTunServer(t, "rust", "")
	proxy := newFreezeProxy(t, srv.addr)
	host, _ := startTunClient(t, Config{
		ServerURL:         "http://" + proxy.addr(),
		PathPrefix:        "v1",
		WebsocketProtocol: "rust",
		PingFrequency:     100 * time.Millisecond,
	}, fastRetry)

	waitEcho(t, host, "before freeze")
	if n := proxy.accepted.Load(); n != 1 {
		t.Fatalf("proxy accepted %d connections before the freeze, want 1", n)
	}

	proxy.freeze()
	deadline := time.Now().Add(10 * time.Second)
	for proxy.accepted.Load() < 2 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if n := proxy.accepted.Load(); n < 2 {
		t.Fatalf("proxy accepted %d connections; the silent HTTP/2 peer was never dropped and re-established", n)
	}
	waitEcho(t, host, "after reconnect")
}

func TestRunTunHTTP2KeepaliveOffWhenPingFrequencyIsZero(t *testing.T) {
	srv := newTestTunServer(t, "rust", "")
	proxy := newFreezeProxy(t, srv.addr)
	host, _ := startTunClient(t, Config{
		ServerURL:         "http://" + proxy.addr(),
		PathPrefix:        "v1",
		WebsocketProtocol: "rust",
	}, fastRetry)
	waitEcho(t, host, "up")
	proxy.freeze()
	time.Sleep(1500 * time.Millisecond)
	if n := proxy.accepted.Load(); n != 1 {
		t.Fatalf("proxy accepted %d connections; PingFrequency 0 must disable dead-peer detection", n)
	}
}

func TestRunTunOverIPv6Server(t *testing.T) {
	ln, err := net.Listen("tcp", "[::1]:0")
	if err != nil {
		t.Skipf("no IPv6 loopback: %v", err)
	}
	_ = ln.Close()
	for _, tc := range []struct{ name, mode, scheme string }{
		{"rust websocket", "rust", "ws"},
		{"rfc6455 websocket", "ws", "ws"},
		{"http2", "rust", "http"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := newTestTunServer(t, tc.mode, "[::1]:0")
			host, _ := startTunClient(t, Config{
				ServerURL:         tc.scheme + "://" + srv.addr,
				PathPrefix:        "v1",
				WebsocketProtocol: tc.mode,
			}, fastRetry)
			waitEcho(t, host, "v6 "+tc.name)
		})
	}
}

func TestRunTunOverTLSWithSelfSignedCert(t *testing.T) {
	for _, tc := range []struct{ name, mode, scheme string }{
		{"rust websocket", "rust", "wss"},
		{"rfc6455 websocket", "ws", "wss"},
		{"http2", "rust", "https"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := newTestTunServerTLS(t, tc.mode, "", true)
			host, _ := startTunClient(t, Config{
				ServerURL:         tc.scheme + "://" + srv.addr,
				PathPrefix:        "v1",
				WebsocketProtocol: tc.mode,
				TlsVerifyCert:     false, // the server's certificate is self-signed
			}, fastRetry)
			waitEcho(t, host, "tls "+tc.name)
		})
	}
}
