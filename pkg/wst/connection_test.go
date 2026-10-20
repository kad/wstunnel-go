package wst

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"errors"
	"math/big"
	"net"
	"sync/atomic"
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

// A control frame must give up at its deadline when a data write holds the
// connection, instead of queueing behind it indefinitely.
func TestWriteControlHonoursDeadline(t *testing.T) {
	a, b := net.Pipe() // unbuffered: a write blocks until b reads
	defer func() { _ = a.Close() }()
	defer func() { _ = b.Close() }()
	c := NewConn(a, false)
	go func() { _ = c.WriteMessage(BinaryMessage, make([]byte, 1<<20)) }() // nobody reads b
	time.Sleep(50 * time.Millisecond)

	start := time.Now()
	err := c.WriteControl(PongMessage, nil, time.Now().Add(100*time.Millisecond))
	if !errors.Is(err, ErrControlTimeout) {
		t.Fatalf("WriteControl err = %v, want ErrControlTimeout", err)
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("WriteControl took %v, want about the 100ms deadline", elapsed)
	}
}

// The default ping handler drops a pong it cannot write in time, so the reader
// keeps draining instead of stalling behind a congested writer.
func TestPingHandlerDoesNotStallReader(t *testing.T) {
	a, b := net.Pipe()
	defer func() { _ = a.Close() }()
	defer func() { _ = b.Close() }()
	c := NewConn(a, false)
	// A reader on a, fed by a raw ping then a data frame from the other side.
	go func() {
		_, _ = b.Write([]byte{0x80 | PingMessage, 0})
		_, _ = b.Write([]byte{0x80 | BinaryMessage, 2, 'h', 'i'})
	}()
	go func() { _ = c.WriteMessage(BinaryMessage, make([]byte, 1<<20)) }() // holds the write lock
	time.Sleep(50 * time.Millisecond)

	got := make(chan error, 1)
	go func() {
		mt, p, err := c.ReadMessage()
		if err == nil && (mt != BinaryMessage || string(p) != "hi") {
			err = errors.New("unexpected message")
		}
		got <- err
	}()
	select {
	case err := <-got:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("ReadMessage stuck behind the pong write")
	}
}

func TestFrameHookSeesEveryFrame(t *testing.T) {
	a, b := net.Pipe()
	defer func() { _ = a.Close() }()
	defer func() { _ = b.Close() }()
	c := NewConn(a, false)
	var n atomic.Int32
	c.SetFrameHook(func() { n.Add(1) })
	go func() {
		_, _ = b.Write([]byte{0x80 | PongMessage, 0})
		_, _ = b.Write([]byte{0x80 | BinaryMessage, 1, 'x'})
	}()
	if _, _, err := c.ReadMessage(); err != nil {
		t.Fatal(err)
	}
	// One per frame header (pong, data) plus one per payload chunk read.
	if n.Load() != 3 {
		t.Fatalf("hook calls = %d, want 3 (pong header, data header, data chunk)", n.Load())
	}
}

// A control write that times out must not poison the connection. On a tls.Conn
// a write deadline error is permanent, so WriteControl must not rely on one:
// after the timeout the frame is still delivered whole and the next message
// goes through.
func TestWriteControlTimeoutKeepsTLSConnUsable(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     []string{"localhost"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
	leaf, _ := x509.ParseCertificate(der)
	pool := x509.NewCertPool()
	pool.AddCert(leaf)

	rawS, rawC := net.Pipe() // unbuffered: a write blocks until the other side reads
	srvTLS := tls.Server(rawS, &tls.Config{Certificates: []tls.Certificate{cert}})
	cliTLS := tls.Client(rawC, &tls.Config{RootCAs: pool, ServerName: "localhost"})
	// Close the pipes first: tls.Conn.Close waits up to 5s to send its alert.
	defer func() { _ = srvTLS.Close() }()
	defer func() { _ = cliTLS.Close() }()
	defer func() { _ = rawS.Close(); _ = rawC.Close() }()
	hs := make(chan error, 2)
	go func() { hs <- srvTLS.Handshake() }()
	go func() { hs <- cliTLS.Handshake() }()
	for range 2 {
		if err := <-hs; err != nil {
			t.Fatal(err)
		}
	}

	srv := NewConn(srvTLS, false)
	cli := NewConn(cliTLS, false)

	// The client is not reading, so the pong cannot be written yet.
	err = srv.WriteControl(PongMessage, []byte("late"), time.Now().Add(100*time.Millisecond))
	if !errors.Is(err, ErrControlTimeout) {
		t.Fatalf("WriteControl err = %v, want ErrControlTimeout", err)
	}

	got := make(chan error, 1)
	go func() {
		// The pong is consumed by the default handler; the data frame follows.
		mt, p, err := cli.ReadMessage()
		if err == nil && (mt != BinaryMessage || string(p) != "after") {
			err = errors.New("unexpected message")
		}
		got <- err
	}()
	if err := srv.WriteMessage(BinaryMessage, []byte("after")); err != nil {
		t.Fatalf("WriteMessage after a control timeout: %v", err)
	}
	select {
	case err := <-got:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("data frame never arrived after the control timeout")
	}
}

// A large frame that trickles in over a slow link keeps reporting activity as
// the bytes arrive, so a liveness watchdog does not mistake it for silence
// before the frame completes.
func TestFrameHookFiresAsPayloadBytesArrive(t *testing.T) {
	a, b := net.Pipe()
	defer func() { _ = a.Close() }()
	defer func() { _ = b.Close() }()
	c := NewConn(a, false)
	var n atomic.Int32
	c.SetFrameHook(func() { n.Add(1) })

	const piece, pieces = 1024, 8
	go func() {
		_, _ = b.Write(binary.BigEndian.AppendUint64([]byte{0x80 | BinaryMessage, 127}, piece*pieces))
		for range pieces {
			_, _ = b.Write(make([]byte, piece))
			time.Sleep(5 * time.Millisecond)
		}
	}()
	_, p, err := c.ReadMessage()
	if err != nil || len(p) != piece*pieces {
		t.Fatalf("ReadMessage: %d bytes, %v", len(p), err)
	}
	// One call for the header, then one per piece that arrived on its own.
	if n.Load() < pieces+1 {
		t.Fatalf("hook calls = %d, want at least %d", n.Load(), pieces+1)
	}
}
