package client

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/kad/wstunnel-go/pkg/tun/tuntest"
	"github.com/kad/wstunnel-go/pkg/wst"
)

// silentServer upgrades the websocket and then never reads, so pings are never
// answered. It counts the sessions it accepted.
func silentServer(t *testing.T, mode string) (addr string, accepted *atomic.Int32) {
	t.Helper()
	accepted = new(atomic.Int32)
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var sub []string
		if strings.Contains(r.Header.Get("Sec-WebSocket-Protocol"), "v1") {
			sub = []string{"v1"}
		}
		if mode == "ws" {
			up := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }, Subprotocols: sub}
			conn, err := up.Upgrade(w, r, nil)
			if err != nil {
				return
			}
			defer func() { _ = conn.Close() }()
		} else {
			up := wst.Upgrader{CheckOrigin: func(*http.Request) bool { return true }, Subprotocols: sub}
			conn, err := up.Upgrade(w, r, nil)
			if err != nil {
				return
			}
			defer func() { _ = conn.Close() }()
		}
		accepted.Add(1)
		<-release
	})
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewUnstartedServer(h)
	srv.Listener = ln
	srv.Start()
	t.Cleanup(srv.Close)
	return ln.Addr().String(), accepted
}

func TestRunTunDropsSilentPeer(t *testing.T) {
	for _, mode := range []string{"rust", "ws"} {
		t.Run(mode, func(t *testing.T) {
			addr, accepted := silentServer(t, mode)
			devEnd, _ := tuntest.Pipe()
			c := NewClient(Config{
				ServerURL:         "ws://" + addr,
				PathPrefix:        "v1",
				WebsocketProtocol: mode,
				PingFrequency:     50 * time.Millisecond,
			})
			ctx, cancel := context.WithCancel(context.Background())
			done := make(chan error, 1)
			go func() { done <- c.runTun(ctx, devEnd, 1500, fastRetry) }()

			deadline := time.Now().Add(5 * time.Second)
			for accepted.Load() < 2 && time.Now().Before(deadline) {
				time.Sleep(20 * time.Millisecond)
			}
			if n := accepted.Load(); n < 2 {
				t.Fatalf("accepted %d sessions; the dead session was never dropped and re-established", n)
			}
			select {
			case err := <-done:
				t.Fatalf("runTun returned %v while it should keep reconnecting", err)
			default:
			}
			cancel()
			select {
			case err := <-done:
				if err != nil {
					t.Fatalf("runTun = %v after cancel, want nil", err)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("runTun did not return after cancel")
			}
		})
	}
}

type countingHandler struct {
	next http.Handler
	n    atomic.Int32
}

func (h *countingHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.n.Add(1)
	h.next.ServeHTTP(w, r)
}

func TestRunTunKeepsResponsivePeer(t *testing.T) {
	for _, mode := range []string{"rust", "ws"} {
		t.Run(mode, func(t *testing.T) {
			real := newTestTunServer(t, mode, "")
			counter := &countingHandler{next: real.srv.Config.Handler}
			real.srv.Config.Handler = counter

			host, _ := startTunClient(t, Config{
				ServerURL:         "ws://" + real.addr,
				PathPrefix:        "v1",
				WebsocketProtocol: mode,
				PingFrequency:     50 * time.Millisecond,
			}, fastRetry)
			dst := tcpEcho(t)

			deadline := time.Now().Add(5 * time.Second)
			var err error
			for time.Now().Before(deadline) {
				if err = echoOnce(t, host, dst, "first"); err == nil {
					break
				}
				time.Sleep(20 * time.Millisecond)
			}
			if err != nil {
				t.Fatalf("no echo: %v", err)
			}
			time.Sleep(500 * time.Millisecond)
			if err := echoOnce(t, host, dst, "after idle"); err != nil {
				t.Fatalf("echo after several ping intervals: %v", err)
			}
			if n := counter.n.Load(); n != 1 {
				t.Fatalf("server saw %d connections, want 1 (a healthy session was dropped)", n)
			}
		})
	}
}
