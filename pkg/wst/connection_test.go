package wst

import (
	"bytes"
	"net"
	"testing"
)

func TestConn_ReadWriteMessage(t *testing.T) {
	// Use net.Pipe to test real-ish connection
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

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
	go func() {
		// Server sends Ping
		err := s.WriteMessage(PingMessage, []byte("ping"))
		if err != nil {
			t.Errorf("Server WriteMessage(Ping) error = %v", err)
		}
	}()

	// Client ReadMessage should automatically reply with Pong and then we read it back on server?
	// Wait, ReadMessage on client side will handle Ping and send Pong.
	// So we need another goroutine to read on client.
	
	clientDone := make(chan struct{})
	go func() {
		// Client reads the Ping, handles it (sends Pong), and we might get an error if we don't expect more
		_, _, _ = c.ReadMessage() 
		close(clientDone)
	}()

	// Server should be able to read the Pong
	opcode, payload, err = s.ReadMessage()
	if err != nil {
		t.Fatalf("Server ReadMessage(Pong) error = %v", err)
	}
	if opcode != PongMessage {
		t.Errorf("Server ReadMessage() opcode = %v, want %v", opcode, PongMessage)
	}
	if string(payload) != "ping" {
		t.Errorf("Server ReadMessage() payload = %s, want ping", string(payload))
	}
	<-clientDone
}

func TestConn_LargeMessage(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

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
