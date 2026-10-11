package client

import (
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

	"github.com/kad/wstunnel-go/pkg/tun/tuntest"
)

func TestBackoffSequence(t *testing.T) {
	b := newBackoff(defaultTunRetry)
	var got []time.Duration
	for range 8 {
		got = append(got, b.next(0))
	}
	want := []time.Duration{1, 2, 4, 8, 16, 30, 30, 30}
	for i := range want {
		if got[i] != want[i]*time.Second {
			t.Fatalf("delays = %v, want 1s,2s,4s,8s,16s,30s,30s,30s", got)
		}
	}
	// A session that lived long enough resets the delay; a short one does not.
	if d := b.next(defaultTunRetry.stable); d != time.Second {
		t.Fatalf("delay after a stable session = %v, want 1s", d)
	}
	if d := b.next(time.Second); d != 2*time.Second {
		t.Fatalf("delay after a short session = %v, want 2s", d)
	}
}

// recordingSleep replaces the retry sleep: it records the delay and returns
// immediately, and cancels the run after n sleeps.
type recordingSleep struct {
	mu     sync.Mutex
	delays []time.Duration
	n      int
	cancel context.CancelFunc
}

func (r *recordingSleep) sleep(ctx context.Context, d time.Duration) {
	r.mu.Lock()
	r.delays = append(r.delays, d)
	enough := len(r.delays) >= r.n
	r.mu.Unlock()
	if enough {
		r.cancel()
	}
}

func TestRunTunPreConnectRunsPerAttemptAndFailureBacksOff(t *testing.T) {
	devEnd, _ := tuntest.Pipe()
	c := NewClient(Config{ServerURL: "ws://127.0.0.1:1", PathPrefix: "v1", WebsocketProtocol: "rust"})
	ctx, cancel := context.WithCancel(context.Background())
	rec := &recordingSleep{n: 7, cancel: cancel}
	retry := defaultTunRetry
	retry.sleep = rec.sleep

	var calls atomic.Int32
	hook := func(context.Context) error {
		calls.Add(1)
		return errors.New("guard says no")
	}
	if err := c.runTun(ctx, devEnd, 1500, retry, hook); err != nil {
		t.Fatalf("runTun = %v", err)
	}
	if got := calls.Load(); got != 7 {
		t.Fatalf("hook ran %d times, want once per attempt (7)", got)
	}
	want := []time.Duration{1, 2, 4, 8, 16, 30, 30}
	for i, d := range rec.delays {
		if d != want[i]*time.Second {
			t.Fatalf("delays = %v, want 1s,2s,4s,8s,16s,30s,30s", rec.delays)
		}
	}
}

func TestRunTunFailedPreConnectNeverDials(t *testing.T) {
	addr, accepted := silentServer(t, "rust")
	devEnd, _ := tuntest.Pipe()
	c := NewClient(Config{ServerURL: "ws://" + addr, PathPrefix: "v1", WebsocketProtocol: "rust"})
	ctx, cancel := context.WithCancel(context.Background())
	rec := &recordingSleep{n: 5, cancel: cancel}
	retry := fastRetry
	retry.sleep = rec.sleep
	_ = c.runTun(ctx, devEnd, 1500, retry, func(context.Context) error { return errors.New("no") })
	if n := accepted.Load(); n != 0 {
		t.Fatalf("server accepted %d sessions although the pre-connect hook failed", n)
	}
}

func TestRunTunPreConnectRunsBeforeEverySession(t *testing.T) {
	addr, accepted := silentServer(t, "rust")
	devEnd, _ := tuntest.Pipe()
	c := NewClient(Config{ServerURL: "ws://" + addr, PathPrefix: "v1", WebsocketProtocol: "rust", PingFrequency: 50 * time.Millisecond})
	ctx, cancel := context.WithCancel(context.Background())
	var calls atomic.Int32
	done := make(chan error, 1)
	go func() {
		done <- c.runTun(ctx, devEnd, 1500, fastRetry, func(context.Context) error { calls.Add(1); return nil })
	}()
	deadline := time.Now().Add(5 * time.Second)
	for accepted.Load() < 2 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	cancel()
	<-done
	if accepted.Load() < 2 {
		t.Fatalf("only %d sessions; need a reconnect to test the hook", accepted.Load())
	}
	if calls.Load() < accepted.Load() {
		t.Fatalf("hook ran %d times for %d sessions", calls.Load(), accepted.Load())
	}
}

func TestRunTunDelayResetsAfterStableSession(t *testing.T) {
	// A server that completes the upgrade and hangs up straight away: each
	// session ends at once. With a clock that makes every session look long, the
	// delay must stay at its minimum.
	srv := newTestTunServer(t, "rust", "")
	devEnd, _ := tuntest.Pipe()
	c := NewClient(Config{ServerURL: "ws://" + srv.addr, PathPrefix: "v1", WebsocketProtocol: "rust"})
	ctx, cancel := context.WithCancel(context.Background())
	rec := &recordingSleep{n: 3, cancel: cancel}
	var tick atomic.Int64
	retry := defaultTunRetry
	retry.sleep = rec.sleep
	base := time.Now()
	retry.now = func() time.Time { return base.Add(time.Duration(tick.Add(1)) * time.Hour) }
	go func() {
		for ctx.Err() == nil {
			srv.ln.closeAll()
			time.Sleep(10 * time.Millisecond)
		}
	}()
	if err := c.runTun(ctx, devEnd, 1500, retry, nil); err != nil {
		t.Fatal(err)
	}
	for _, d := range rec.delays {
		if d != time.Second {
			t.Fatalf("delays = %v, want all 1s after stable sessions", rec.delays)
		}
	}
}

func TestCheckTunLoops(t *testing.T) {
	spec := mustSpec(t, "tun://wst0?route=10.0.0.0/8")
	if err := checkTunLoops(spec, []netip.Addr{netip.MustParseAddr("203.0.113.5")}); err != nil {
		t.Fatalf("unrelated server: %v", err)
	}
	if err := checkTunLoops(spec, []netip.Addr{netip.MustParseAddr("10.1.2.3")}); err == nil || !strings.Contains(err.Error(), "loop") {
		t.Fatalf("server inside a route = %v, want a loop error", err)
	}
	if err := checkTunLoops(spec, nil); err == nil {
		t.Fatal("no known server address must fail closed")
	}
}

func TestTunGuardFollowsDNSAndFallsBack(t *testing.T) {
	orig := lookupNetIP
	t.Cleanup(func() { lookupNetIP = orig })
	var mu sync.Mutex
	answer := []netip.Addr{netip.MustParseAddr("203.0.113.5")}
	var lookupErr error
	lookupNetIP = func(context.Context, string) ([]netip.Addr, error) {
		mu.Lock()
		defer mu.Unlock()
		return answer, lookupErr
	}
	set := func(a []netip.Addr, err error) {
		mu.Lock()
		answer, lookupErr = a, err
		mu.Unlock()
	}

	c := NewClient(Config{ServerURL: "wss://tun.example.test"})
	spec := mustSpec(t, "tun://wst0?route=10.0.0.0/8")
	guard := c.newTunGuard(spec, nil)
	ctx := context.Background()

	if err := guard(ctx); err != nil {
		t.Fatalf("first attempt: %v", err)
	}
	// The name now resolves into a routed network: the guard must refuse.
	set([]netip.Addr{netip.MustParseAddr("10.9.9.9")}, nil)
	if err := guard(ctx); err == nil || !strings.Contains(err.Error(), "loop") {
		t.Fatalf("changed DNS answer = %v, want a loop error", err)
	}
	// Re-resolution fails or comes back empty: the last known good addresses
	// (the answer from the first attempt, 203.0.113.5) are checked instead.
	// The refused answer must not have replaced them.
	set(nil, errors.New("dns down"))
	if err := guard(ctx); err != nil {
		t.Fatalf("lookup failure with known addresses: %v", err)
	}
	set(nil, nil)
	if err := guard(ctx); err != nil {
		t.Fatalf("empty lookup with known addresses: %v", err)
	}
}

func TestTunGuardFailsClosedWithoutAnyResolution(t *testing.T) {
	orig := lookupNetIP
	t.Cleanup(func() { lookupNetIP = orig })
	lookupNetIP = func(context.Context, string) ([]netip.Addr, error) { return nil, errors.New("dns down") }
	c := NewClient(Config{ServerURL: "wss://tun.example.test"})
	guard := c.newTunGuard(mustSpec(t, "tun://wst0?route=10.0.0.0/8"), nil)
	if err := guard(context.Background()); err == nil {
		t.Fatal("guard passed although the server address was never known")
	}
}

type countingCloser struct {
	closed atomic.Int32
}

func (c *countingCloser) Read([]byte) (int, error)  { return 0, io.EOF }
func (c *countingCloser) Write([]byte) (int, error) { return 0, io.EOF }
func (c *countingCloser) Close() error              { c.closed.Add(1); return nil }

func TestConnectWithContextClosesLateStream(t *testing.T) {
	release := make(chan struct{})
	late := &countingCloser{}
	dial := func() *tunnelStream {
		<-release
		return &tunnelStream{h2: late}
	}
	ctx, cancel := context.WithCancel(context.Background())
	got := make(chan *tunnelStream, 1)
	go func() { got <- connectWithContext(ctx, dial) }()
	cancel()
	ts := <-got
	if ts.err == nil || !errors.Is(ts.err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", ts.err)
	}
	if late.closed.Load() != 0 {
		t.Fatal("stream closed before it existed")
	}
	close(release)
	deadline := time.Now().Add(2 * time.Second)
	for late.closed.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if late.closed.Load() != 1 {
		t.Fatalf("late stream closed %d times, want 1", late.closed.Load())
	}
}

func TestConnectWithContextReturnsResultWhenInTime(t *testing.T) {
	s := &countingCloser{}
	ts := connectWithContext(context.Background(), func() *tunnelStream { return &tunnelStream{h2: s} })
	if ts.err != nil || ts.h2 != s {
		t.Fatalf("ts = %+v", ts)
	}
	if s.closed.Load() != 0 {
		t.Fatal("a stream delivered in time must not be closed")
	}
}

func TestTunHandleCloseDuringHangingDial(t *testing.T) {
	// Accepts the TCP connection and never answers the websocket upgrade.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	accepted := make(chan struct{}, 1)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			select {
			case accepted <- struct{}{}:
			default:
			}
			t.Cleanup(func() { _ = c.Close() })
		}
	}()

	devEnd, _ := tuntest.Pipe()
	c := NewClient(Config{ServerURL: "ws://" + ln.Addr().String(), PathPrefix: "v1", WebsocketProtocol: "rust"})
	h := c.startTunHandle(context.Background(), devEnd, "tun-test", 1500, fastRetry, nil, nil)
	select {
	case <-accepted:
	case <-time.After(5 * time.Second):
		t.Fatal("the client never dialled")
	}

	closed := make(chan struct{})
	go func() { _ = h.Close(); close(closed) }()
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("Close did not return within 1s while a dial was pending")
	}
}
