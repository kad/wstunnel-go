package client

import (
	"context"
	"net"
	"testing"
)

func TestConnectionPoolGetAfterCloseReturnsErrClosed(t *testing.T) {
	serverConn, clientConn := net.Pipe()
	defer func() { _ = serverConn.Close() }()

	pool := &ConnectionPool{
		conns: make(chan net.Conn, 1),
	}
	pool.conns <- clientConn

	pool.Close()

	if _, err := pool.Get(context.Background()); err != net.ErrClosed {
		t.Fatalf("Get() error = %v, want %v", err, net.ErrClosed)
	}
}
