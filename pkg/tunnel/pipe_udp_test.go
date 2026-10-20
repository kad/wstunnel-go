package tunnel

import (
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

// Every WebSocket message must reach a UDP destination as exactly one datagram:
// a fragmented message is not split, and an empty one is not dropped.
func TestPipeGorillaKeepsUDPMessageBoundaries(t *testing.T) {
	sink, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = sink.Close() }()
	out, err := net.DialUDP("udp", nil, sink.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ws, err := (&websocket.Upgrader{}).Upgrade(w, r, nil)
		if err != nil {
			return
		}
		PipeGorillaLive(out, ws, nil)
	}))
	defer srv.Close()
	// A tiny write buffer makes the client send a fragment per 16 bytes.
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
	for range 3 {
		if _, err := w.Write(make([]byte, 16)); err != nil {
			t.Fatal(err)
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if err := c.WriteMessage(websocket.BinaryMessage, nil); err != nil {
		t.Fatal(err)
	}
	if err := c.WriteMessage(websocket.BinaryMessage, []byte("hello")); err != nil {
		t.Fatal(err)
	}

	buf := make([]byte, 2048)
	for i, want := range []int{48, 0, 5} {
		_ = sink.SetReadDeadline(time.Now().Add(3 * time.Second))
		n, _, err := sink.ReadFromUDP(buf)
		if err != nil {
			t.Fatalf("datagram %d: %v", i, err)
		}
		if n != want {
			t.Fatalf("datagram %d is %d bytes, want %d (message boundary lost)", i, n, want)
		}
	}
}

// Forwarding many small messages must not allocate a copy buffer for each one.
func TestGorillaToWriterReusesItsCopyBuffer(t *testing.T) {
	const messages = 2000
	finished := make(chan struct{})
	var before, after runtime.MemStats
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ws, err := (&websocket.Upgrader{}).Upgrade(w, r, nil)
		if err != nil {
			return
		}
		gorillaToWriter(ws, io.Discard, newLiveness())
		close(finished)
	}))
	defer srv.Close()
	c, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(srv.URL, "http"), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()

	runtime.GC()
	runtime.ReadMemStats(&before)
	for range messages {
		if err := c.WriteMessage(websocket.BinaryMessage, []byte("x")); err != nil {
			t.Fatal(err)
		}
	}
	_ = c.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""))
	select {
	case <-finished:
	case <-time.After(5 * time.Second):
		t.Fatal("forwarder did not finish")
	}
	runtime.ReadMemStats(&after)
	// A fresh 32 KiB buffer per message would be 64 MB here.
	if got := after.TotalAlloc - before.TotalAlloc; got > 16<<20 {
		t.Fatalf("allocated %d bytes for %d one byte messages, want far less than a copy buffer each", got, messages)
	}
}
