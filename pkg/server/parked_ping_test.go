package server

import (
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/kad/wstunnel-go/pkg/protocol"
	"github.com/kad/wstunnel-go/pkg/wst"
)

func parkedClaims(id string) *protocol.JwtTunnelConfig {
	return &protocol.JwtTunnelConfig{
		ID:       id,
		Remote:   "127.0.0.1",
		Port:     0,
		Protocol: protocol.LocalProtocol{ReverseTcp: &struct{}{}},
	}
}

func parkedServer(t *testing.T, mgr *ReverseTunnelManager, claims *protocol.JwtTunnelConfig) (*websocket.Conn, <-chan struct{}) {
	t.Helper()
	returned := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ws, err := (&websocket.Upgrader{}).Upgrade(w, r, nil)
		if err != nil {
			return
		}
		mgr.HandleGorillaClient(ws, claims)
		close(returned)
	}))
	t.Cleanup(srv.Close)
	c, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(srv.URL, "http"), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c, returned
}

// A parked reverse connection is pinged so the client can tell a quiet server
// from a dead one.
func TestParkedReverseConnectionIsPinged(t *testing.T) {
	mgr := NewReverseTunnelManager(0, 10*time.Second).withPingInterval(20 * time.Millisecond)
	t.Cleanup(mgr.Close)
	c, _ := parkedServer(t, mgr, parkedClaims("parked-ping"))

	var pings atomic.Int32
	c.SetPingHandler(func(string) error { pings.Add(1); return nil })
	go func() {
		for {
			if _, _, err := c.ReadMessage(); err != nil {
				return
			}
		}
	}()

	deadline := time.Now().Add(2 * time.Second)
	for pings.Load() < 3 {
		if time.Now().After(deadline) {
			t.Fatalf("got %d pings on a parked connection, want at least 3", pings.Load())
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// A parked client that vanished frees its slot at the next ping instead of
// waiting for the idle timeout.
func TestParkedReverseConnectionDroppedWhenPeerGone(t *testing.T) {
	mgr := NewReverseTunnelManager(0, time.Minute).withPingInterval(20 * time.Millisecond)
	t.Cleanup(mgr.Close)
	c, returned := parkedServer(t, mgr, parkedClaims("parked-gone"))

	time.Sleep(60 * time.Millisecond)
	_ = c.UnderlyingConn().Close()

	select {
	case <-returned:
	case <-time.After(3 * time.Second):
		t.Fatal("parked connection of a vanished client was not released")
	}
}

func TestReverseWakeHeaderAdvertisesPing(t *testing.T) {
	h := reverseWakeHeader(parkedClaims("h"), 1500*time.Millisecond)
	if h.Get(ReverseWakeHeader) == "" || h.Get(ReversePingHeader) != "1500" {
		t.Fatalf("headers = %v, want wake and ping=1500", h)
	}
	if got := reverseWakeHeader(parkedClaims("h"), 0).Get(ReversePingHeader); got != "" {
		t.Fatalf("ping header = %q with pings disabled, want none", got)
	}
}

// When the pool for a listener is full, an extra client waits for a place. The
// response already promised pings, so it must be pinged while it waits, and it
// must give up as soon as it goes away instead of piling up as a stuck handler.
func TestHeartbeatsStartBeforePoolAdmission(t *testing.T) {
	mgr := NewReverseTunnelManager(0, time.Minute).withPingInterval(20 * time.Millisecond)
	t.Cleanup(mgr.Close)
	claims := parkedClaims("parked-full")

	// Fill the pool (ten slots) so the next client queues for admission.
	for range 10 {
		parkedServer(t, mgr, claims)
	}
	extra, returned := parkedServer(t, mgr, claims)

	var pings atomic.Int32
	extra.SetPingHandler(func(string) error { pings.Add(1); return nil })
	go func() {
		for {
			if _, _, err := extra.ReadMessage(); err != nil {
				return
			}
		}
	}()
	deadline := time.Now().Add(2 * time.Second)
	for pings.Load() < 3 {
		if time.Now().After(deadline) {
			t.Fatalf("a client waiting for a pool slot got %d pings, want at least 3", pings.Load())
		}
		time.Sleep(10 * time.Millisecond)
	}

	_ = extra.UnderlyingConn().Close()
	select {
	case <-returned:
	case <-time.After(3 * time.Second):
		t.Fatal("handler of a vanished client stayed blocked waiting for a pool slot")
	}
}

// A parked client that stopped draining leaves a timed out ping holding the
// write lock. When a visitor acquires that connection, the wake-up frame blocks
// on the lock, and acquiring ended the parked idle timeout. The watchdog has to
// be running by then, or the visitor hangs for good.
func TestWakeUpFrameBlockedOnStalledClientIsBounded(t *testing.T) {
	mgr := NewReverseTunnelManager(0, time.Minute).withPingInterval(30 * time.Millisecond)
	t.Cleanup(mgr.Close)
	tl, _, err := mgr.getOrCreateListener(parkedClaims("stalled-wake"))
	if err != nil {
		t.Fatal(err)
	}

	server, client := net.Pipe() // unbuffered, and the client never reads
	defer func() { _ = client.Close() }()
	wait := &waitingConn{
		wsConn:   wst.NewConn(server, false),
		acquired: make(chan struct{}),
		done:     make(chan struct{}),
	}
	mgr.pingParked(tl, wait)
	if !mgr.enqueueWaitingConn(tl, wait) {
		t.Fatal("could not queue the parked connection")
	}
	time.Sleep(150 * time.Millisecond) // a ping times out and its write keeps the lock

	visitor, far := net.Pipe()
	defer func() { _ = far.Close() }()
	done := make(chan struct{})
	go func() {
		mgr.handleIncoming(tl, visitor)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("a visitor stayed stuck on the wake-up frame of a stalled parked client")
	}
}
