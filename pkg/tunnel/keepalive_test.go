package tunnel

import (
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/kad/wstunnel-go/pkg/wst"
)

// A peer that stays connected but never answers pings must not hold a pipe
// open forever.
func TestWatchWstClosesUnresponsivePeer(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()

	silent := make(chan net.Conn, 1)
	go func() {
		c, _ := ln.Accept()
		silent <- c // accepted, never read or written
	}()
	raw, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	peer := <-silent
	defer func() { _ = peer.Close() }()

	local, remote := net.Pipe()
	defer func() { _ = remote.Close() }()

	done := make(chan struct{})
	go func() {
		wsConn := wst.NewConn(raw, false)
		stop, live := WatchWst(wsConn, 20*time.Millisecond)
		PipeLive(local, wsConn, live)
		stop()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("pipe stayed open although the peer never answered a ping")
	}
}

// Data from the peer proves it is alive even when it never answers a ping (its
// pong may be stuck behind its own bulk writes); the pipe must stay open.
func TestWatchWstKeepsPipeWhileDataFlows(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	peerCh := make(chan net.Conn, 1)
	go func() {
		c, _ := ln.Accept()
		peerCh <- c
	}()
	raw, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	peer := <-peerCh
	defer func() { _ = peer.Close() }()

	local, remote := net.Pipe()
	defer func() { _ = remote.Close() }()
	go func() { _, _ = io.Copy(io.Discard, remote) }()

	done := make(chan struct{})
	go func() {
		wsConn := wst.NewConn(raw, false)
		stop, live := WatchWst(wsConn, 20*time.Millisecond)
		PipeLive(local, wsConn, live)
		stop()
		close(done)
	}()

	// Binary frames only, never a pong, for far longer than 3 ping intervals.
	end := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(end) {
		if _, err := peer.Write([]byte{0x80 | wst.BinaryMessage, 1, 'x'}); err != nil {
			t.Fatal(err)
		}
		select {
		case <-done:
			t.Fatal("watchdog closed a peer that was sending data")
		case <-time.After(10 * time.Millisecond):
		}
	}
	_ = peer.Close()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("pipe did not end after the peer closed")
	}
}

func TestWatchGorillaKeepsPipeWhileDataFlows(t *testing.T) {
	ready := make(chan struct{})
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		up := websocket.Upgrader{}
		ws, err := up.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		local, remote := net.Pipe()
		defer func() { _ = remote.Close() }()
		go func() { _, _ = io.Copy(io.Discard, remote) }()
		stop, live := WatchGorilla(ws, 20*time.Millisecond)
		close(ready)
		PipeGorillaLive(local, ws, live)
		stop()
		close(release)
	}))
	defer srv.Close()

	c, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(srv.URL, "http"), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	<-ready
	// The client never reads, so it never answers a ping.
	end := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(end) {
		if err := c.WriteMessage(websocket.BinaryMessage, []byte("x")); err != nil {
			t.Fatalf("server closed a peer that was sending data: %v", err)
		}
		select {
		case <-release:
			t.Fatal("watchdog ended the pipe while data flowed")
		case <-time.After(10 * time.Millisecond):
		}
	}
	_ = c.Close()
	select {
	case <-release:
	case <-time.After(3 * time.Second):
		t.Fatal("pipe did not end after the peer closed")
	}
}

type fakeNetErr struct{ timeout, temporary bool }

func (e fakeNetErr) Error() string   { return "fake" }
func (e fakeNetErr) Timeout() bool   { return e.timeout }
func (e fakeNetErr) Temporary() bool { return e.temporary }

func TestIsTransientWriteTimeout(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"wst lock wait", wst.ErrControlTimeout, true},
		{"wrapped wst lock wait", fmt.Errorf("ping: %w", wst.ErrControlTimeout), true},
		{"gorilla lock wait (timeout and temporary)", fakeNetErr{true, true}, true},
		{"gorilla cached socket timeout (timeout, not temporary)", fakeNetErr{true, false}, false},
		{"other net error", fakeNetErr{false, false}, false},
		{"plain error", errors.New("boom"), false},
	}
	for _, tc := range cases {
		if got := IsTransientWriteTimeout(tc.err); got != tc.want {
			t.Errorf("%s: IsTransientWriteTimeout = %v, want %v", tc.name, got, tc.want)
		}
	}
}

// A bulk write that holds the write lock makes the ping time out. A peer that
// keeps sending is alive, so the watchdog must skip that ping, not close.
func TestWatchWstSkipsPingBlockedByBulkWrite(t *testing.T) {
	a, b := net.Pipe()
	defer func() { _ = a.Close() }()
	defer func() { _ = b.Close() }()
	c := wst.NewConn(a, false)
	go func() { _ = c.WriteMessage(wst.BinaryMessage, make([]byte, 1<<20)) }() // b never reads: holds the lock
	time.Sleep(50 * time.Millisecond)

	stop, _ := WatchWst(c, 20*time.Millisecond)
	defer stop()
	readErr := make(chan error, 1)
	go func() {
		for {
			if _, _, err := c.ReadMessage(); err != nil {
				readErr <- err
				return
			}
		}
	}()

	end := time.Now().Add(400 * time.Millisecond) // far more than 3 intervals
	for time.Now().Before(end) {
		if _, err := b.Write([]byte{0x80 | wst.BinaryMessage, 1, 'x'}); err != nil {
			t.Fatalf("watchdog closed a congested but live connection: %v", err)
		}
		select {
		case err := <-readErr:
			t.Fatalf("watchdog closed a congested but live connection: %v", err)
		case <-time.After(10 * time.Millisecond):
		}
	}
}

// The pipe stops reading the connection while it writes the peer's data to a
// local destination that has stopped draining. That is not silence from the
// peer, so the watchdog must not close a connection it cannot see into.
func TestWatchWstSuspendsWhileDownstreamWriteBlocked(t *testing.T) {
	a, b := net.Pipe()
	defer func() { _ = a.Close() }()
	defer func() { _ = b.Close() }()
	local, remote := net.Pipe() // remote is not read yet: writes to local block

	done := make(chan struct{})
	go func() {
		wsConn := wst.NewConn(a, false)
		stop, live := WatchWst(wsConn, 20*time.Millisecond)
		PipeLive(local, wsConn, live)
		stop()
		close(done)
	}()

	// The pipe stays stuck in its downstream write, so `done` cannot show a
	// close; the peer sees it as EOF on its own end instead.
	peerSawClose := make(chan struct{})
	go func() {
		_, _ = io.Copy(io.Discard, b)
		close(peerSawClose)
	}()
	if _, err := b.Write([]byte{0x80 | wst.BinaryMessage, 4, 'd', 'a', 't', 'a'}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-peerSawClose:
		t.Fatal("watchdog closed a connection whose pipe was blocked on a slow local destination")
	case <-time.After(400 * time.Millisecond): // many times 3 intervals
	}

	go func() { _, _ = io.Copy(io.Discard, remote) }() // the destination recovers
	_ = b.Close()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("pipe did not end after the peer closed")
	}
	_ = remote.Close()
}

func TestWatchGorillaSuspendsWhileDownstreamWriteBlocked(t *testing.T) {
	local, remote := net.Pipe()
	done := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ws, err := (&websocket.Upgrader{}).Upgrade(w, r, nil)
		if err != nil {
			return
		}
		stop, live := WatchGorilla(ws, 20*time.Millisecond)
		PipeGorillaLive(local, ws, live)
		stop()
		close(done)
	}))
	defer srv.Close()
	c, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(srv.URL, "http"), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()

	peerSawClose := make(chan struct{})
	go func() {
		for {
			if _, _, err := c.ReadMessage(); err != nil {
				close(peerSawClose)
				return
			}
		}
	}()
	if err := c.WriteMessage(websocket.BinaryMessage, []byte("data")); err != nil {
		t.Fatal(err)
	}
	select {
	case <-peerSawClose:
		t.Fatal("watchdog closed a connection whose pipe was blocked on a slow local destination")
	case <-time.After(400 * time.Millisecond):
	}
	go func() { _, _ = io.Copy(io.Discard, remote) }()
	_ = c.Close()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("pipe did not end after the peer closed")
	}
	_ = remote.Close()
}

// A message sent as many fragments is not complete until the last one, but
// every fragment is a sign of life. The peer here never answers a ping.
func TestWatchGorillaCountsFragmentsOfALongMessage(t *testing.T) {
	received := make(chan int, 1)
	done := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ws, err := (&websocket.Upgrader{}).Upgrade(w, r, nil)
		if err != nil {
			return
		}
		local, remote := net.Pipe()
		go func() {
			n, _ := io.Copy(io.Discard, remote)
			received <- int(n)
		}()
		stop, live := WatchGorilla(ws, 20*time.Millisecond)
		PipeGorillaLive(local, ws, live)
		stop()
		close(done)
	}))
	defer srv.Close()

	// A tiny write buffer makes the client flush a fragment per 16 bytes.
	d := websocket.Dialer{WriteBufferSize: 16}
	c, _, err := d.Dial("ws"+strings.TrimPrefix(srv.URL, "http"), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	w, err := c.NextWriter(websocket.BinaryMessage)
	if err != nil {
		t.Fatal(err)
	}
	const fragments = 25 // 250ms of trickle against a 60ms silence limit
	for range fragments {
		if _, err := w.Write(make([]byte, 16)); err != nil {
			t.Fatalf("server closed during a streaming message: %v", err)
		}
		select {
		case <-done:
			t.Fatal("watchdog closed a peer that was streaming a fragmented message")
		case <-time.After(10 * time.Millisecond):
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	_ = c.Close()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("pipe did not end")
	}
	if got := <-received; got != fragments*16 {
		t.Fatalf("forwarded %d bytes, want %d", got, fragments*16)
	}
}

// The ping handler a caller installed may block behind a bulk write; the
// watchdog replaces it with the bounded default, or the reader would stall and
// stop refreshing the very liveness the watchdog checks.
func TestWatchWstReplacesBlockingPingHandler(t *testing.T) {
	a, b := net.Pipe()
	defer func() { _ = a.Close() }()
	defer func() { _ = b.Close() }()
	c := wst.NewConn(a, false)
	c.SetPingHandler(func(appData string) error { // the old server handler
		return c.WriteMessage(wst.PongMessage, []byte(appData))
	})
	go func() { _ = c.WriteMessage(wst.BinaryMessage, make([]byte, 1<<20)) }() // holds the write lock
	time.Sleep(50 * time.Millisecond)
	stop, _ := WatchWst(c, time.Hour)
	defer stop()

	go func() {
		_, _ = b.Write([]byte{0x80 | wst.PingMessage, 0})
		_, _ = b.Write([]byte{0x80 | wst.BinaryMessage, 1, 'x'})
	}()
	got := make(chan error, 1)
	go func() {
		_, p, err := c.ReadMessage()
		if err == nil && string(p) != "x" {
			err = io.ErrUnexpectedEOF
		}
		got <- err
	}()
	select {
	case err := <-got:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("ReadMessage stuck answering a ping behind a bulk write")
	}
}

// Answering a ping can hold the reader for up to a second when a bulk write
// owns the write lock. With a short ping interval the watchdog limit (three
// intervals) is shorter than that, and the peer's queued frames cannot be read
// meanwhile. That wait is ours, not silence from the peer.
func TestWatchWstDoesNotExpireWhileReaderWaitsToPong(t *testing.T) {
	a, b := net.Pipe()
	defer func() { _ = a.Close() }()
	defer func() { _ = b.Close() }()
	c := wst.NewConn(a, false)
	go func() { _ = c.WriteMessage(wst.BinaryMessage, make([]byte, 1<<20)) }() // holds the write lock
	time.Sleep(50 * time.Millisecond)
	stop, _ := WatchWst(c, 50*time.Millisecond) // limit: 150ms, pong wait: 1s
	defer stop()

	readErr := make(chan error, 1)
	go func() {
		for {
			if _, _, err := c.ReadMessage(); err != nil {
				readErr <- err
				return
			}
		}
	}()
	go func() { // a ping, then data that waits unread behind the pong
		_, _ = b.Write([]byte{0x80 | wst.PingMessage, 0})
		for range 200 {
			if _, err := b.Write([]byte{0x80 | wst.BinaryMessage, 1, 'x'}); err != nil {
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
	}()

	select {
	case err := <-readErr:
		t.Fatalf("watchdog closed a live connection while the reader waited to send a pong: %v", err)
	case <-time.After(2 * time.Second):
	}
}

func TestWatchGorillaDoesNotExpireWhileReaderWaitsToPong(t *testing.T) {
	local, remote := net.Pipe()
	defer func() { _ = remote.Close() }()
	go func() { _, _ = io.Copy(io.Discard, remote) }() // what the client sends ends up here
	go func() {                                        // bulk data toward the client, which never reads it
		buf := make([]byte, 1<<20)
		for {
			if _, err := remote.Write(buf); err != nil {
				return
			}
		}
	}()
	done := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ws, err := (&websocket.Upgrader{}).Upgrade(w, r, nil)
		if err != nil {
			return
		}
		stop, live := WatchGorilla(ws, 50*time.Millisecond) // limit: 150ms, pong wait: 1s
		PipeGorillaLive(local, ws, live)                    // its writer ends up holding the write lock
		stop()
		close(done)
	}))
	defer srv.Close()
	c, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(srv.URL, "http"), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()

	// The client keeps sending, so the connection is live throughout. After the
	// socket buffers have filled, its ping makes the server's reader wait.
	for i := range 250 {
		if i == 70 {
			if err := c.WriteControl(websocket.PingMessage, nil, time.Now().Add(time.Second)); err != nil {
				t.Fatal(err)
			}
		}
		if err := c.WriteMessage(websocket.BinaryMessage, []byte("x")); err != nil {
			t.Fatalf("server closed a live connection while its reader waited to send a pong: %v", err)
		}
		select {
		case <-done:
			t.Fatal("watchdog closed a live connection while the reader waited to send a pong")
		case <-time.After(10 * time.Millisecond):
		}
	}
}

// PingWst keeps pinging but never expires for silence: it is for a connection
// the peer may legitimately not be reading.
func TestPingWstKeepsASilentPeerOpen(t *testing.T) {
	a, b := net.Pipe()
	defer func() { _ = a.Close() }()
	go func() { _, _ = io.Copy(io.Discard, b) }() // takes the pings, answers nothing
	local, remote := net.Pipe()
	defer func() { _ = remote.Close() }()

	done := make(chan struct{})
	go func() {
		wsConn := wst.NewConn(a, false)
		stop, live := PingWst(wsConn, 20*time.Millisecond)
		PipeLive(local, wsConn, live)
		stop()
		close(done)
	}()
	select {
	case <-done:
		t.Fatal("PingWst closed a silent peer; it must only ping")
	case <-time.After(400 * time.Millisecond): // many times 3 intervals
	}
	_ = b.Close()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("pipe did not end after the peer closed")
	}
}
