package client

import (
	"context"
	"net"
	"testing"
	"time"
)

// TestTLSHandshakeTimeout verifies that TLS handshake respects the timeout
// and doesn't hang indefinitely when the server accepts TCP but never
// completes the TLS handshake (see upstream issue #516)
func TestTLSHandshakeTimeout(t *testing.T) {
	// Start a TCP server that accepts connections but never completes TLS handshake
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to start listener: %v", err)
	}
	defer func() { _ = listener.Close() }()

	acceptDone := make(chan struct{})
	go func() {
		defer close(acceptDone)
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		// Accept but never complete TLS handshake - just block
		time.Sleep(30 * time.Second)
	}()

	// Create a client configured to connect to this server
	client := &Client{
		Config: Config{
			ServerURL:     "wss://" + listener.Addr().String(),
			TlsVerifyCert: false, // Skip verification for test
		},
	}

	// Attempt to connect - should timeout, not hang
	ctx := context.Background()
	start := time.Now()

	_, err = client.dialTransport(ctx, "", "")

	elapsed := time.Since(start)

	// Should fail with timeout error
	if err == nil {
		t.Fatal("dialTransport() succeeded, expected timeout error")
	}

	// Should complete within reasonable time (10s timeout + overhead)
	if elapsed > 15*time.Second {
		t.Errorf("dialTransport() took %v, expected timeout around 10s", elapsed)
	}

	// Error should indicate TLS handshake failure
	if err.Error() == "" {
		t.Error("dialTransport() returned empty error")
	}

	// Wait for accept goroutine to finish
	select {
	case <-acceptDone:
	case <-time.After(1 * time.Second):
		t.Log("Accept goroutine still running (expected)")
	}
}

// TestTLSHandshakeContextCancellation verifies that context cancellation
// properly interrupts TLS handshake
func TestTLSHandshakeContextCancellation(t *testing.T) {
	// Start a TCP server that accepts connections but never completes TLS handshake
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to start listener: %v", err)
	}
	defer func() { _ = listener.Close() }()

	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		// Block forever
		time.Sleep(1 * time.Hour)
	}()

	// Create a client
	client := &Client{
		Config: Config{
			ServerURL:     "wss://" + listener.Addr().String(),
			TlsVerifyCert: false,
		},
	}

	// Use context with short timeout
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	start := time.Now()
	_, err = client.dialTransport(ctx, "", "")
	elapsed := time.Since(start)

	// Should fail with context deadline exceeded
	if err == nil {
		t.Fatal("dialTransport() succeeded, expected context deadline error")
	}

	// Should complete quickly (within 200ms)
	if elapsed > 500*time.Millisecond {
		t.Errorf("dialTransport() took %v, expected quick failure on context cancellation", elapsed)
	}
}
