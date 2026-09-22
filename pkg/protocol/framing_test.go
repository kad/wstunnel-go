package protocol

import (
	"bytes"
	"encoding/binary"
	"io"
	"testing"
)

type testReadWriteCloser struct {
	*bytes.Reader
}

func (testReadWriteCloser) Write(p []byte) (int, error) {
	return len(p), nil
}

func (testReadWriteCloser) Close() error {
	return nil
}

type shortWriteReadWriteCloser struct {
	bytes.Buffer
	maxWrite int
}

func (c *shortWriteReadWriteCloser) Read(_ []byte) (int, error) {
	return 0, io.EOF
}

func (c *shortWriteReadWriteCloser) Write(p []byte) (int, error) {
	if len(p) > c.maxWrite {
		p = p[:c.maxWrite]
	}
	return c.Buffer.Write(p)
}

func (c *shortWriteReadWriteCloser) Close() error {
	return nil
}

func TestFramedUDPReadWriteCloserReadPreservesLargeDatagram(t *testing.T) {
	payload := []byte("large udp payload")
	nextPayload := []byte("next packet")
	var framed bytes.Buffer
	for _, packet := range [][]byte{payload, nextPayload} {
		var lenBuf [2]byte
		binary.BigEndian.PutUint16(lenBuf[:], uint16(len(packet)))
		framed.Write(lenBuf[:])
		framed.Write(packet)
	}

	rwc := NewFramedUDPReadWriteCloser(testReadWriteCloser{bytes.NewReader(framed.Bytes())})
	var received []byte
	buf := make([]byte, 3)
	for len(received) < len(payload) {
		n, err := rwc.Read(buf)
		if err != nil {
			t.Fatalf("Read() error = %v", err)
		}
		received = append(received, buf[:n]...)
	}
	if !bytes.Equal(received, payload) {
		t.Fatalf("received payload = %q, want %q", received, payload)
	}

	next := make([]byte, len(nextPayload))
	n, err := io.ReadFull(rwc, next)
	if err != nil {
		t.Fatalf("ReadFull() error = %v", err)
	}
	if n != len(nextPayload) || !bytes.Equal(next, nextPayload) {
		t.Fatalf("next payload = %q, want %q", next[:n], nextPayload)
	}
}

func TestFramedUDPReadWriteCloserReadPacketPreservesLargeAndEmptyDatagrams(t *testing.T) {
	largePayload := bytes.Repeat([]byte("x"), 65535)
	var framed bytes.Buffer
	for _, packet := range [][]byte{largePayload, {}} {
		var lenBuf [2]byte
		binary.BigEndian.PutUint16(lenBuf[:], uint16(len(packet)))
		framed.Write(lenBuf[:])
		framed.Write(packet)
	}

	rwc := NewFramedUDPReadWriteCloser(testReadWriteCloser{bytes.NewReader(framed.Bytes())})
	packet, err := rwc.ReadPacket()
	if err != nil {
		t.Fatalf("ReadPacket() error = %v", err)
	}
	if !bytes.Equal(packet, largePayload) {
		t.Fatal("ReadPacket() did not preserve the large datagram")
	}

	packet, err = rwc.ReadPacket()
	if err != nil {
		t.Fatalf("ReadPacket() error = %v", err)
	}
	if len(packet) != 0 {
		t.Fatalf("ReadPacket() returned %d bytes, want an empty datagram", len(packet))
	}
}

func TestFramedUDPReadWriteCloserWriteHandlesShortWrites(t *testing.T) {
	underlying := &shortWriteReadWriteCloser{maxWrite: 2}
	rwc := NewFramedUDPReadWriteCloser(underlying)
	payload := []byte("udp payload")

	n, err := rwc.Write(payload)
	if err != nil {
		t.Fatalf("Write() error = %v", err)
	}
	if n != len(payload) {
		t.Fatalf("Write() wrote %d bytes, want %d", n, len(payload))
	}

	var expected bytes.Buffer
	var lenBuf [2]byte
	binary.BigEndian.PutUint16(lenBuf[:], uint16(len(payload)))
	expected.Write(lenBuf[:])
	expected.Write(payload)
	if !bytes.Equal(underlying.Bytes(), expected.Bytes()) {
		t.Fatalf("written frame = %x, want %x", underlying.Bytes(), expected.Bytes())
	}
}

func TestWriteJWTStreamPreambleHandlesShortWrites(t *testing.T) {
	underlying := &shortWriteReadWriteCloser{maxWrite: 1}
	const jwt = "jwt payload"

	if err := WriteJWTStreamPreamble(underlying, jwt); err != nil {
		t.Fatalf("WriteJWTStreamPreamble() error = %v", err)
	}

	var expected bytes.Buffer
	var lenBuf [2]byte
	binary.BigEndian.PutUint16(lenBuf[:], uint16(len(jwt)))
	expected.Write(lenBuf[:])
	expected.WriteString(jwt)
	if !bytes.Equal(underlying.Bytes(), expected.Bytes()) {
		t.Fatalf("written preamble = %x, want %x", underlying.Bytes(), expected.Bytes())
	}
}
