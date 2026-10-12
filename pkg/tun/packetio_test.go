package tun_test

import (
	"bytes"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/kad/wstunnel-go/pkg/tun"
	"github.com/kad/wstunnel-go/pkg/wst"
)

// packetSizes covers the empty packet, a typical MTU, and the u16 maximum.
var packetSizes = []int{0, 1, 1500, 9000, tun.MaxPacketSize}

func packetOf(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i * 7)
	}
	return b
}

func roundTrip(t *testing.T, a, b tun.PacketConn) {
	t.Helper()
	errc := make(chan error, 1)
	go func() {
		for _, n := range packetSizes {
			if err := a.WritePacket(packetOf(n)); err != nil {
				errc <- err
				return
			}
		}
		errc <- nil
	}()
	for _, n := range packetSizes {
		got, err := b.ReadPacket()
		if err != nil {
			t.Fatalf("ReadPacket(size %d): %v", n, err)
		}
		if !bytes.Equal(got, packetOf(n)) {
			t.Fatalf("packet of size %d corrupted: got %d bytes", n, len(got))
		}
	}
	if err := <-errc; err != nil {
		t.Fatalf("WritePacket: %v", err)
	}
	if err := a.WritePacket(make([]byte, tun.MaxPacketSize+1)); !errors.Is(err, tun.ErrPacketTooLarge) {
		t.Fatalf("oversized WritePacket error = %v, want ErrPacketTooLarge", err)
	}
}

func TestFramedPacketConnRoundTrip(t *testing.T) {
	a, b := net.Pipe()
	roundTrip(t, tun.NewFramedPacketConn(a), tun.NewFramedPacketConn(b))
}

func TestWSTPacketConnRoundTrip(t *testing.T) {
	a, b := net.Pipe()
	// Client side masks with the zero key, server side does not: the same
	// asymmetry the Rust-compatible transport uses.
	roundTrip(t, tun.NewWSTPacketConn(wst.NewConn(a, true)), tun.NewWSTPacketConn(wst.NewConn(b, false)))
}

func TestGorillaPacketConnRoundTrip(t *testing.T) {
	serverConn := make(chan *websocket.Conn, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := (&websocket.Upgrader{}).Upgrade(w, r, nil)
		if err != nil {
			t.Errorf("upgrade: %v", err)
			return
		}
		serverConn <- c
	}))
	defer srv.Close()

	cc, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(srv.URL, "http"), nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	sc := <-serverConn
	a, b := tun.NewGorillaPacketConn(cc), tun.NewGorillaPacketConn(sc)
	defer func() { _ = a.Close(); _ = b.Close() }()
	roundTrip(t, a, b)
}

func TestWSTPacketConnSkipsTextMessages(t *testing.T) {
	a, b := net.Pipe()
	ca, cb := wst.NewConn(a, true), wst.NewConn(b, false)
	go func() {
		_ = ca.WriteMessage(wst.TextMessage, []byte("ignored"))
		_ = ca.WriteMessage(wst.BinaryMessage, []byte{0x45})
	}()
	got, err := tun.NewWSTPacketConn(cb).ReadPacket()
	if err != nil || !bytes.Equal(got, []byte{0x45}) {
		t.Fatalf("ReadPacket = %v, %v; want [0x45], nil", got, err)
	}
}

// An oversized message must be cut off at the read limit, not buffered, and
// Serve must report it as a failure rather than a clean disconnect.
func TestGorillaPacketConnEnforcesReadLimit(t *testing.T) {
	served := make(chan error, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := (&websocket.Upgrader{}).Upgrade(w, r, nil)
		if err != nil {
			served <- err
			return
		}
		served <- tun.Serve(r.Context(), tun.NewGorillaPacketConn(c), tun.Options{
			Authorize: func(tun.Flow) bool { return false },
		})
	}))
	defer srv.Close()

	c, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(srv.URL, "http"), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	if err := c.WriteMessage(websocket.BinaryMessage, make([]byte, tun.MaxPacketSize+1)); err != nil {
		t.Fatal(err)
	}

	select {
	case err := <-served:
		if !errors.Is(err, websocket.ErrReadLimit) {
			t.Fatalf("Serve error = %v, want websocket.ErrReadLimit", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Serve did not return after an oversized message")
	}
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, _, err := c.ReadMessage(); err == nil {
		t.Fatal("connection still readable after oversized message")
	}
}

// The custom WebSocket reader must refuse an oversized frame from its header,
// as the gorilla adapter does with SetReadLimit: with only the header sent, a
// reader that allocated the announced payload (up to 10 MiB) would block.
func TestWSTPacketConnRefusesOversizedFrameFromTheHeader(t *testing.T) {
	client, server := net.Pipe()
	defer func() { _ = client.Close() }()
	defer func() { _ = server.Close() }()
	pc := tun.NewWSTPacketConn(wst.NewConn(server, false))

	go func() {
		// binary frame announcing 5 MiB, payload never sent
		_, _ = client.Write([]byte{0x82, 127, 0, 0, 0, 0, 0, 0x50, 0, 0})
	}()
	done := make(chan error, 1)
	go func() {
		_, err := pc.ReadPacket()
		done <- err
	}()
	select {
	case err := <-done:
		if !errors.Is(err, wst.ErrReadLimit) {
			t.Fatalf("ReadPacket error = %v, want wst.ErrReadLimit", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("ReadPacket waited for the payload of an oversized frame")
	}
}
