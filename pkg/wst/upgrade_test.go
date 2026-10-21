package wst

import (
	"bufio"
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// Headers given to Upgrade must reach the client in the 101 response. The
// reverse tunnel announces its wake-up frame and ping interval this way.
func TestUpgradeSendsResponseHeaders(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u := Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
		c, err := u.Upgrade(w, r, http.Header{
			"X-Wstunnel-Reverse-Wake": []string{"1"},
			"X-Wstunnel-Reverse-Ping": []string{"1500"},
			"Connection":              []string{"close"},              // handshake header: ignored
			"X-Injected":              []string{"a\r\nX-Smuggled: 1"}, // line break: dropped
			"Bad\r\nName":             []string{"x"},                  // line break in the name: dropped
			"Sec-WebSocket-Accept":    []string{"forged"},             // handshake header: ignored
			"X-Multi":                 []string{"one", "two"},
		})
		if err != nil {
			return
		}
		_ = c.Close()
	}))
	defer srv.Close()

	c, resp, err := DefaultDialer.Dial("ws"+strings.TrimPrefix(srv.URL, "http"), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()

	if got := resp.Header.Get("X-Wstunnel-Reverse-Wake"); got != "1" {
		t.Errorf("wake header = %q, want 1", got)
	}
	if got := resp.Header.Get("X-Wstunnel-Reverse-Ping"); got != "1500" {
		t.Errorf("ping header = %q, want 1500", got)
	}
	if got := resp.Header.Values("X-Multi"); len(got) != 2 {
		t.Errorf("X-Multi = %v, want both values", got)
	}
	if got := resp.Header.Get("Connection"); !strings.EqualFold(got, "Upgrade") {
		t.Errorf("Connection = %q, want Upgrade (handshake headers are not overridable)", got)
	}
	if got := resp.Header.Get("Sec-WebSocket-Accept"); got == "forged" || got == "" {
		t.Errorf("Sec-WebSocket-Accept = %q, want the real accept key", got)
	}
	if resp.Header.Get("X-Smuggled") != "" || resp.Header.Get("X-Injected") != "" {
		t.Errorf("a header with a line break got through: %v", resp.Header)
	}
}

// stalledHijacker hands out one end of a pipe whose other end never reads.
type stalledHijacker struct {
	http.ResponseWriter
	conn net.Conn
}

func (h stalledHijacker) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	return h.conn, bufio.NewReadWriter(bufio.NewReader(h.conn), bufio.NewWriter(h.conn)), nil
}

// A client that never reads the 101 response must not hold Upgrade for good.
func TestUpgradeGivesUpOnStalledClient(t *testing.T) {
	server, client := net.Pipe()
	defer func() { _ = server.Close() }()
	defer func() { _ = client.Close() }()

	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("Connection", "Upgrade")
	r.Header.Set("Upgrade", "websocket")
	r.Header.Set("Sec-WebSocket-Version", "13")
	r.Header.Set("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")

	done := make(chan error, 1)
	go func() {
		u := Upgrader{WriteTimeout: 100 * time.Millisecond}
		_, err := u.Upgrade(stalledHijacker{httptest.NewRecorder(), server}, r, nil)
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("Upgrade succeeded although nobody read the response")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Upgrade is still blocked on a client that does not read")
	}
}

// A handshake that is cut short by its context fails with the context's reason,
// so a timeout can be told from a refusal.
func TestDialContextKeepsTheReasonItWasCutShort(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			defer func() { _ = c.Close() }() // answers nothing
		}
	}()
	url := "ws://" + ln.Addr().String() + "/x"

	t.Run("handshake timeout", func(t *testing.T) {
		d := &Dialer{HandshakeTimeout: 200 * time.Millisecond}
		_, _, err := d.DialContext(context.Background(), url, nil)
		var ne net.Error
		timeout := errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &ne) && ne.Timeout())
		if !timeout {
			t.Fatalf("err = %v, want a timeout", err)
		}
	})
	t.Run("cancelled", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		go func() { time.Sleep(200 * time.Millisecond); cancel() }()
		d := &Dialer{HandshakeTimeout: 5 * time.Second}
		_, _, err := d.DialContext(ctx, url, nil)
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("err = %v, want context.Canceled", err)
		}
	})
}
