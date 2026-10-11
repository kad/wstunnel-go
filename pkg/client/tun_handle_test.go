package client

import (
	"context"
	"errors"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kad/wstunnel-go/pkg/tun"
	"github.com/kad/wstunnel-go/pkg/tun/tuntest"
)

// tunGoroutines lists the stacks of goroutines that belong to the tun client
// loop. After Close returns there must be none: Close waits for them.
func tunGoroutines() []string {
	buf := make([]byte, 1<<20)
	buf = buf[:runtime.Stack(buf, true)]
	var found []string
	for _, g := range strings.Split(string(buf), "\n\n") {
		// An abandoned dial cannot be interrupted (see connectWithContext); it
		// ends on its own timeout and closes whatever it opened.
		if strings.Contains(g, "connectWithContext") {
			continue
		}
		for _, fn := range []string{"(*Client).runTun", "(*Client).tunSession", "(*Client).tunKeepAlive"} {
			if strings.Contains(g, "pkg/client."+fn) {
				found = append(found, g)
				break
			}
		}
	}
	return found
}

func newHandleForTest(t *testing.T, cleanups ...func() error) (*TunHandle, *closeCountingDevice) {
	t.Helper()
	srv := newTestTunServer(t, "rust", "")
	devEnd, hostEnd := tuntest.Pipe()
	dev := &closeCountingDevice{PacketConn: devEnd}
	host := tuntest.NewHost(t, hostEnd, 1500)
	c := NewClient(Config{ServerURL: "ws://" + srv.addr, PathPrefix: "v1", WebsocketProtocol: "rust", PingFrequency: 50 * time.Millisecond})
	h := c.startTunHandle(context.Background(), dev, "tun-test", 1500, fastRetry, nil, cleanups)
	t.Cleanup(func() { _ = h.Close() })

	// Wait for a live session so Close has keepalive and pump goroutines to stop.
	dst := tcpEcho(t)
	deadline := time.Now().Add(5 * time.Second)
	for echoOnce(t, host, dst, "up") != nil {
		if time.Now().After(deadline) {
			t.Fatal("tun session never came up")
		}
	}
	return h, dev
}

type closeCountingDevice struct {
	tun.PacketConn
	closed atomic.Int32
}

func (d *closeCountingDevice) Close() error {
	d.closed.Add(1)
	return d.PacketConn.Close()
}

func TestTunHandleCloseStopsLoopAndClosesDevice(t *testing.T) {
	var cleaned atomic.Int32
	h, dev := newHandleForTest(t, func() error { cleaned.Add(1); return nil })
	select {
	case <-h.Done():
		t.Fatal("Done fired before Close")
	default:
	}
	if h.Err() != nil {
		t.Fatalf("Err before Done = %v, want nil", h.Err())
	}
	if err := h.Close(); err != nil {
		t.Fatalf("Close = %v", err)
	}
	select {
	case <-h.Done():
	default:
		t.Fatal("Done not closed after Close returned")
	}
	if h.Err() != nil {
		t.Fatalf("Err after clean Close = %v, want nil", h.Err())
	}
	if dev.closed.Load() == 0 {
		t.Fatal("Close did not close the device")
	}
	if cleaned.Load() != 1 {
		t.Fatalf("cleanup ran %d times, want 1", cleaned.Load())
	}
	if g := tunGoroutines(); len(g) != 0 {
		t.Fatalf("goroutines left after Close:\n%s", strings.Join(g, "\n\n"))
	}
}

func TestTunHandleCloseIsIdempotentAndConcurrent(t *testing.T) {
	var cleaned atomic.Int32
	h, _ := newHandleForTest(t, func() error { cleaned.Add(1); return nil })
	errs := make(chan error, 4)
	for range 4 {
		go func() { errs <- h.Close() }()
	}
	for range 4 {
		if err := <-errs; err != nil {
			t.Errorf("Close = %v", err)
		}
	}
	if err := h.Close(); err != nil {
		t.Errorf("Close after Close = %v", err)
	}
	if cleaned.Load() != 1 {
		t.Fatalf("cleanup ran %d times, want exactly 1", cleaned.Load())
	}
}

func TestTunHandleDoneCarriesDeviceError(t *testing.T) {
	srv := newTestTunServer(t, "rust", "")
	devEnd, hostEnd := tuntest.Pipe()
	var cleaned atomic.Int32
	c := NewClient(Config{ServerURL: "ws://" + srv.addr, PathPrefix: "v1", WebsocketProtocol: "rust"})
	h := c.startTunHandle(context.Background(), devEnd, "tun-test", 1500, fastRetry, nil, []func() error{func() error { cleaned.Add(1); return nil }})
	t.Cleanup(func() { _ = h.Close() })

	_ = hostEnd.Close() // the device disappears
	select {
	case <-h.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("Done did not fire after the device failed")
	}
	if h.Err() == nil {
		t.Fatal("Err = nil after a device failure")
	}
	if cleaned.Load() != 1 {
		t.Fatalf("cleanup ran %d times after a fatal error, want 1", cleaned.Load())
	}
	if err := h.Close(); errors.Is(err, context.Canceled) {
		t.Fatalf("Close after failure = %v", err)
	}
	if g := tunGoroutines(); len(g) != 0 {
		t.Fatalf("goroutines left after failure:\n%s", strings.Join(g, "\n\n"))
	}
}

func TestTunHandleParentContextEndsIt(t *testing.T) {
	srv := newTestTunServer(t, "rust", "")
	devEnd, _ := tuntest.Pipe()
	c := NewClient(Config{ServerURL: "ws://" + srv.addr, PathPrefix: "v1", WebsocketProtocol: "rust"})
	ctx, cancel := context.WithCancel(context.Background())
	h := c.startTunHandle(ctx, devEnd, "tun-test", 1500, fastRetry, nil, nil)
	cancel()
	select {
	case <-h.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("Done did not fire after the parent context ended")
	}
	if h.Err() != nil {
		t.Fatalf("Err = %v, want nil for a cancelled parent context", h.Err())
	}
}

func TestTunHandleCleanupErrorsSurfaceFromClose(t *testing.T) {
	boom := errors.New("boom")
	h, _ := newHandleForTest(t, func() error { return boom })
	if err := h.Close(); !errors.Is(err, boom) {
		t.Fatalf("Close = %v, want the cleanup error", err)
	}
}
