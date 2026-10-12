package wst

import (
	"bytes"
	"errors"
	"net"
	"testing"
	"time"
)

func TestConn_ReadWriteMessage(t *testing.T) {
	// Use net.Pipe to test real-ish connection
	client, server := net.Pipe()
	defer func() { _ = client.Close() }()
	defer func() { _ = server.Close() }()

	c := NewConn(client, true)  // Client masks
	s := NewConn(server, false) // Server doesn't mask

	data := []byte("hello world")

	// Test Binary Message
	go func() {
		err := c.WriteMessage(BinaryMessage, data)
		if err != nil {
			t.Errorf("WriteMessage() error = %v", err)
		}
	}()

	opcode, payload, err := s.ReadMessage()
	if err != nil {
		t.Fatalf("ReadMessage() error = %v", err)
	}
	if opcode != BinaryMessage {
		t.Errorf("ReadMessage() opcode = %v, want %v", opcode, BinaryMessage)
	}
	if !bytes.Equal(payload, data) {
		t.Errorf("ReadMessage() payload = %s, want %s", string(payload), string(data))
	}

	// Test Ping/Pong
	pongReceived := make(chan string, 1)
	s.SetPongHandler(func(msg string) error {
		pongReceived <- msg
		return nil
	})

	go func() {
		// Server sends Ping
		err := s.WriteControl(PingMessage, []byte("ping"), time.Now().Add(time.Second))
		if err != nil {
			t.Errorf("Server WriteControl(Ping) error = %v", err)
		}
	}()

	go func() {
		// Client reads the Ping, handles it (sends Pong automatically via default ping handler).
		_, _, _ = c.ReadMessage()
	}()

	go func() {
		// Server needs to read to trigger handlers
		_, _, _ = s.ReadMessage()
	}()

	// Server should receive the Pong via handler
	select {
	case msg := <-pongReceived:
		if msg != "ping" {
			t.Errorf("Server received wrong pong message: %s", msg)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("Server timed out waiting for Pong")
	}
}

func TestConn_LargeMessage(t *testing.T) {
	client, server := net.Pipe()
	defer func() { _ = client.Close() }()
	defer func() { _ = server.Close() }()

	c := NewConn(client, false)
	s := NewConn(server, false)

	// 70KB message (test 16-bit length)
	data := make([]byte, 70000)
	for i := range data {
		data[i] = byte(i % 256)
	}

	go func() {
		_ = c.WriteMessage(BinaryMessage, data)
	}()

	opcode, payload, err := s.ReadMessage()
	if err != nil {
		t.Fatalf("ReadMessage() error = %v", err)
	}
	if opcode != BinaryMessage {
		t.Errorf("opcode mismatch")
	}
	if !bytes.Equal(payload, data) {
		t.Errorf("payload mismatch")
	}
}

// A peer announcing a payload over the read limit must be refused from the
// frame header alone, before any buffer for the payload is allocated: here the
// payload is never sent, so an implementation that allocates and waits for it
// would block instead of failing.
func TestConn_ReadLimitRefusesOversizedFrameFromTheHeader(t *testing.T) {
	client, server := net.Pipe()
	defer func() { _ = client.Close() }()
	defer func() { _ = server.Close() }()

	s := NewConn(server, false)
	s.SetReadLimit(100)

	go func() {
		// FIN+binary, 8-byte length form announcing 5 MiB, no payload.
		hdr := []byte{0x82, 127, 0, 0, 0, 0, 0, 0x50, 0, 0}
		_, _ = client.Write(hdr)
	}()

	done := make(chan error, 1)
	go func() {
		_, _, err := s.ReadMessage()
		done <- err
	}()
	select {
	case err := <-done:
		if !errors.Is(err, ErrReadLimit) {
			t.Fatalf("ReadMessage() error = %v, want ErrReadLimit", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("ReadMessage waited for the payload of an oversized frame")
	}
}

func TestConn_ReadLimitAllowsMessagesWithinTheLimit(t *testing.T) {
	client, server := net.Pipe()
	defer func() { _ = client.Close() }()
	defer func() { _ = server.Close() }()

	c := NewConn(client, false)
	s := NewConn(server, false)
	s.SetReadLimit(100)
	go func() { _ = c.WriteMessage(BinaryMessage, make([]byte, 100)) }()
	if _, p, err := s.ReadMessage(); err != nil || len(p) != 100 {
		t.Fatalf("ReadMessage() = %d bytes, %v; want 100, nil", len(p), err)
	}
}

// ErrReadLimit is the one error for an oversized frame, whether the limit was
// set by SetReadLimit or is the built-in 10 MiB ceiling.
func TestConn_OversizedFrameAlwaysReportsErrReadLimit(t *testing.T) {
	for name, limit := range map[string]int64{"default ceiling": 0, "configured limit": 100} {
		t.Run(name, func(t *testing.T) {
			client, server := net.Pipe()
			defer func() { _ = client.Close() }()
			defer func() { _ = server.Close() }()
			s := NewConn(server, false)
			s.SetReadLimit(limit)
			go func() {
				// announces 1 GiB
				_, _ = client.Write([]byte{0x82, 127, 0, 0, 0, 0, 0x40, 0, 0, 0})
			}()
			_, _, err := s.ReadMessage()
			if !errors.Is(err, ErrReadLimit) {
				t.Fatalf("ReadMessage() error = %v, want ErrReadLimit", err)
			}
		})
	}
}
