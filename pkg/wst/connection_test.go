package wst

import (
	"bytes"
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
