package tun_test

import (
	"bytes"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

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
