package server

import (
	"io"
	"testing"
	"time"
)

// The client ending only its sending half while the stream is parked is seen at
// once, without anyone reading the stream.
func TestWatchedStreamReportsClientHalfClose(t *testing.T) {
	server, client := pipeRWC()
	w := newWatchedStream(server)
	select {
	case <-w.Gone():
		t.Fatal("reported gone before the client did anything")
	case <-time.After(100 * time.Millisecond):
	}
	_ = client.CloseWrite()
	select {
	case <-w.Gone():
	case <-time.After(3 * time.Second):
		t.Fatal("the client's half-close was not noticed")
	}
	if _, err := w.Read(make([]byte, 8)); err != io.EOF {
		t.Fatalf("read after the half-close: %v, want EOF", err)
	}
}

// A client that sends early is not gone, and its first bytes still reach the
// reader.
func TestWatchedStreamKeepsEarlyPayload(t *testing.T) {
	server, client := pipeRWC()
	w := newWatchedStream(server)
	go func() { _, _ = client.Write([]byte("hello")) }()
	select {
	case <-w.Gone():
		t.Fatal("a client that sent data was reported gone")
	case <-time.After(200 * time.Millisecond):
	}
	got, err := io.ReadAll(io.LimitReader(w, 5))
	if err != nil || string(got) != "hello" {
		t.Fatalf("read %q, %v; want \"hello\"", got, err)
	}
}

// halfPipe is one side of an in-memory duplex stream whose writer can end its
// sending half alone.
type halfPipe struct {
	*io.PipeReader
	*io.PipeWriter
}

func (h halfPipe) Read(p []byte) (int, error)  { return h.PipeReader.Read(p) }
func (h halfPipe) Write(p []byte) (int, error) { return h.PipeWriter.Write(p) }
func (h halfPipe) Close() error {
	_ = h.PipeReader.Close()
	return h.PipeWriter.Close()
}
func (h halfPipe) CloseWrite() error { return h.PipeWriter.Close() }

func pipeRWC() (server io.ReadWriteCloser, client halfPipe) {
	ar, aw := io.Pipe()
	br, bw := io.Pipe()
	return halfPipe{ar, bw}, halfPipe{br, aw}
}
