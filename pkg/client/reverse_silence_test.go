package client

import (
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/kad/wstunnel-go/pkg/wst"
)

// A parked reverse connection whose server advertised pings but went silent
// must end after a few intervals so the reverse loop re-dials.
func TestAwaitReverseTriggerGivesUpOnSilentServer(t *testing.T) {
	hold := make(chan struct{})
	t.Cleanup(func() { close(hold) })
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ws, err := (&websocket.Upgrader{}).Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer func() { _ = ws.Close() }()
		<-hold // alive but silent: no pings, no wake-up frame
	}))
	t.Cleanup(srv.Close)
	ws, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(srv.URL, "http"), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ws.Close() }()

	ts := &tunnelStream{gorilla: ws, r: &http.Response{Header: http.Header{
		"X-Wstunnel-Reverse-Wake": []string{"1"},
		"X-Wstunnel-Reverse-Ping": []string{"30"},
	}}}
	done := make(chan error, 1)
	go func() {
		_, _, err := (&Client{}).awaitReverseTrigger(ts)
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("awaitReverseTrigger returned without error on a silent server")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("awaitReverseTrigger kept waiting on a silent server")
	}
}

// A server that keeps pinging a parked connection is alive, however long the
// wait: ReadMessage answers those pings internally, so they must refresh the
// deadline themselves.
func TestAwaitReverseTriggerSurvivesRegularPings(t *testing.T) {
	const interval = 30 * time.Millisecond // the client allows 3 of them in silence
	var pongs atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ws, err := (&websocket.Upgrader{}).Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer func() { _ = ws.Close() }()
		ws.SetPongHandler(func(string) error { pongs.Add(1); return nil })
		go func() { // read, as a server with an active pipe would
			for {
				if _, _, err := ws.ReadMessage(); err != nil {
					return
				}
			}
		}()
		// Ping for many times the allowed silence, then wake the client.
		for range 15 {
			time.Sleep(interval)
			if ws.WriteControl(websocket.PingMessage, nil, time.Now().Add(time.Second)) != nil {
				return
			}
		}
		_ = ws.WriteMessage(websocket.BinaryMessage, []byte("wake"))
		// Quiet for longer than the silence limit: a pipe that inherited the
		// parked-phase deadline would time out here.
		time.Sleep(8 * interval)
		_ = ws.WriteMessage(websocket.BinaryMessage, []byte("second"))
	}))
	t.Cleanup(srv.Close)
	ws, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(srv.URL, "http"), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ws.Close() }()

	ts := &tunnelStream{gorilla: ws, r: &http.Response{Header: http.Header{
		"X-Wstunnel-Reverse-Wake": []string{"1"},
		"X-Wstunnel-Reverse-Ping": []string{"30"},
	}}}
	data, lazy, err := (&Client{}).awaitReverseTrigger(ts)
	if err != nil {
		t.Fatalf("a pinged parked connection was dropped: %v", err)
	}
	if !lazy || string(data) != "wake" {
		t.Fatalf("got lazy=%v data=%q, want the wake frame", lazy, data)
	}
	// The pipe that follows must not inherit the silence deadline.
	_, p, err := ts.gorilla.ReadMessage()
	if err != nil || string(p) != "second" {
		t.Fatalf("read after the parked phase: %q, %v", p, err)
	}
	// The server does not read a parked connection, so pongs would only pile up
	// in its receive buffer. The client must not send any.
	if n := pongs.Load(); n != 0 {
		t.Fatalf("client sent %d pongs while parked, want none", n)
	}
}

// Same as above for the custom wst transport.
func TestAwaitReverseTriggerSurvivesRegularPingsWst(t *testing.T) {
	const interval = 30 * time.Millisecond
	a, b := net.Pipe()
	defer func() { _ = a.Close() }()
	defer func() { _ = b.Close() }()
	go func() { _, _ = io.Copy(io.Discard, b) }() // drain pongs
	go func() {
		for range 15 {
			time.Sleep(interval)
			if _, err := b.Write([]byte{0x80 | wst.PingMessage, 0}); err != nil {
				return
			}
		}
		_, _ = b.Write([]byte{0x80 | wst.BinaryMessage, 4, 'w', 'a', 'k', 'e'})
		time.Sleep(8 * interval)
		_, _ = b.Write([]byte{0x80 | wst.BinaryMessage, 6, 's', 'e', 'c', 'o', 'n', 'd'})
	}()

	conn := wst.NewConn(a, false)
	ts := &tunnelStream{ws: conn, r: &http.Response{Header: http.Header{
		"X-Wstunnel-Reverse-Wake": []string{"1"},
		"X-Wstunnel-Reverse-Ping": []string{"30"},
	}}}
	data, lazy, err := (&Client{}).awaitReverseTrigger(ts)
	if err != nil || !lazy || string(data) != "wake" {
		t.Fatalf("got data=%q lazy=%v err=%v, want the wake frame", data, lazy, err)
	}
	if _, p, err := conn.ReadMessage(); err != nil || string(p) != "second" {
		t.Fatalf("read after the parked phase: %q, %v", p, err)
	}
}

// A reverse connection dialed eagerly (the server sent no wake-up header) may be
// parked by a legacy server that never reads it, so the client only pings and
// does not expire it for silence. One the server woke up is enforced.
func TestStartPipeModeEnforcesSilenceOnlyWhenAsked(t *testing.T) {
	run := func(enforce bool) (ended bool) {
		a, b := net.Pipe()
		defer func() { _ = a.Close() }()
		go func() { _, _ = io.Copy(io.Discard, b) }() // reads pings, never answers
		local, far := net.Pipe()
		defer func() { _ = far.Close() }()
		c := &Client{Config: Config{PingFrequency: 20 * time.Millisecond}}
		done := make(chan struct{})
		go func() {
			c.startPipeMode(local, &tunnelStream{ws: wst.NewConn(a, false)}, enforce)
			close(done)
		}()
		select {
		case <-done:
			return true
		case <-time.After(500 * time.Millisecond):
			_ = b.Close()
			<-done
			return false
		}
	}
	if !run(true) {
		t.Error("an enforced pipe stayed open against a server silent for many ping intervals")
	}
	if run(false) {
		t.Error("a ping-only pipe expired a silent server; legacy servers never answer pings on a parked connection")
	}
}
