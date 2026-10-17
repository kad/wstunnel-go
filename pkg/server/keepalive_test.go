package server

import (
	"net"
	"testing"
	"time"

	"github.com/kad/wstunnel-go/pkg/tunnel"
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
		stop := watchWst(wsConn, 20*time.Millisecond)
		tunnel.Pipe(local, wsConn)
		stop()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("pipe stayed open although the peer never answered a ping")
	}
}
