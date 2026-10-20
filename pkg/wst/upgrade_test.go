package wst

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
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
