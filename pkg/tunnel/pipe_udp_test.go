package tunnel

import (
	"bytes"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/kad/wstunnel-go/pkg/wst"
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

// udpPair returns a socket for the "remote" side of the test, and a connected
// socket (the one the pipe owns) whose peer is that socket.
func udpPair(t *testing.T) (remote *net.UDPConn, piped *net.UDPConn) {
	t.Helper()
	remote, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	piped, err = net.DialUDP("udp", nil, remote.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = remote.Close(); _ = piped.Close() })
	return remote, piped
}

// A datagram larger than the stream pump's 32 KiB buffer, and an empty one, each
// cross the pipe in both directions as exactly one message and one datagram.
func TestPipesCarryLargeAndEmptyDatagrams(t *testing.T) {
	big := bytes.Repeat([]byte{0xAB}, 60000)
	type end struct {
		send func([]byte) error
		recv func() ([]byte, error)
	}

	check := func(t *testing.T, remote *net.UDPConn, piped *net.UDPConn, peer end) {
		t.Helper()
		_ = remote.SetReadDeadline(time.Now().Add(5 * time.Second))
		for _, payload := range [][]byte{big, {}, []byte("small")} {
			// UDP socket -> pipe -> websocket peer
			if _, err := remote.WriteToUDP(payload, piped.LocalAddr().(*net.UDPAddr)); err != nil {
				t.Fatal(err)
			}
			got, err := peer.recv()
			if err != nil || !bytes.Equal(got, payload) {
				t.Fatalf("to the websocket: got %d bytes, err %v, want %d", len(got), err, len(payload))
			}
			// websocket peer -> pipe -> UDP socket
			if err := peer.send(payload); err != nil {
				t.Fatal(err)
			}
			buf := make([]byte, 65535)
			n, _, err := remote.ReadFromUDP(buf)
			if err != nil || !bytes.Equal(buf[:n], payload) {
				t.Fatalf("to the socket: got %d bytes, err %v, want %d", n, err, len(payload))
			}
		}
	}

	t.Run("wst", func(t *testing.T) {
		remote, piped := udpPair(t)
		a, b := net.Pipe()
		t.Cleanup(func() { _ = a.Close(); _ = b.Close() })
		go PipeLive(piped, wst.NewConn(a, false), nil)
		peer := wst.NewConn(b, false)
		check(t, remote, piped, end{
			send: func(p []byte) error { return peer.WriteMessage(wst.BinaryMessage, p) },
			recv: func() ([]byte, error) { _, p, err := peer.ReadMessage(); return p, err },
		})
	})

	t.Run("gorilla", func(t *testing.T) {
		remote, piped := udpPair(t)
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ws, err := (&websocket.Upgrader{}).Upgrade(w, r, nil)
			if err != nil {
				return
			}
			PipeGorillaLive(piped, ws, nil)
		}))
		defer srv.Close()
		c, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(srv.URL, "http"), nil)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = c.Close() }()
		check(t, remote, piped, end{
			send: func(p []byte) error { return c.WriteMessage(websocket.BinaryMessage, p) },
			recv: func() ([]byte, error) { _, p, err := c.ReadMessage(); return p, err },
		})
	})
}
