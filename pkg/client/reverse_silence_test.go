package client

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/gorilla/websocket"
	"github.com/kad/wstunnel-go/pkg/protocol"
	"github.com/kad/wstunnel-go/pkg/wst"
)

// A parked reverse connection whose server advertised pings but went silent
// must end after a few intervals so the reverse loop re-dials.
func TestAwaitReverseTriggerGivesUpOnSilentServer(t *testing.T) {
	hold := make(chan struct{})
	t.Cleanup(func() { close(hold) })
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ws, err := (&websocket.Upgrader{}).Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer func() { _ = ws.Close() }()
		<-hold // alive but silent: no pings, no wake-up frame
	}))
	t.Cleanup(srv.Close)
	ws, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(srv.URL, "http"), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ws.Close() }()

	ts := &tunnelStream{gorilla: ws, r: &http.Response{Header: http.Header{
		"X-Wstunnel-Reverse-Wake": []string{"1"},
		"X-Wstunnel-Reverse-Ping": []string{"30"},
	}}}
	done := make(chan error, 1)
	go func() {
		_, _, err := (&Client{}).awaitReverseTrigger(ts, false)
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("awaitReverseTrigger returned without error on a silent server")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("awaitReverseTrigger kept waiting on a silent server")
	}
}

// A server that keeps pinging a parked connection is alive, however long the
// wait: ReadMessage answers those pings internally, so they must refresh the
// deadline themselves.
func TestAwaitReverseTriggerSurvivesRegularPings(t *testing.T) {
	const interval = 30 * time.Millisecond // the client allows 3 of them in silence
	var pongs atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ws, err := (&websocket.Upgrader{}).Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer func() { _ = ws.Close() }()
		ws.SetPongHandler(func(string) error { pongs.Add(1); return nil })
		go func() { // read, as a server with an active pipe would
			for {
				if _, _, err := ws.ReadMessage(); err != nil {
					return
				}
			}
		}()
		// Ping for many times the allowed silence, then wake the client.
		for range 15 {
			time.Sleep(interval)
			if ws.WriteControl(websocket.PingMessage, nil, time.Now().Add(time.Second)) != nil {
				return
			}
		}
		_ = ws.WriteMessage(websocket.BinaryMessage, []byte("wake"))
		// Quiet for longer than the silence limit: a pipe that inherited the
		// parked-phase deadline would time out here.
		time.Sleep(8 * interval)
		_ = ws.WriteMessage(websocket.BinaryMessage, []byte("second"))
	}))
	t.Cleanup(srv.Close)
	ws, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(srv.URL, "http"), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ws.Close() }()

	ts := &tunnelStream{gorilla: ws, r: &http.Response{Header: http.Header{
		"X-Wstunnel-Reverse-Wake": []string{"1"},
		"X-Wstunnel-Reverse-Ping": []string{"30"},
	}}}
	data, lazy, err := (&Client{}).awaitReverseTrigger(ts, false)
	if err != nil {
		t.Fatalf("a pinged parked connection was dropped: %v", err)
	}
	if !lazy || string(data) != "wake" {
		t.Fatalf("got lazy=%v data=%q, want the wake frame", lazy, data)
	}
	// The pipe that follows must not inherit the silence deadline.
	_, p, err := ts.gorilla.ReadMessage()
	if err != nil || string(p) != "second" {
		t.Fatalf("read after the parked phase: %q, %v", p, err)
	}
	// The server does not read a parked connection, so pongs would only pile up
	// in its receive buffer. The client must not send any.
	if n := pongs.Load(); n != 0 {
		t.Fatalf("client sent %d pongs while parked, want none", n)
	}
}

// Same as above for the custom wst transport.
func TestAwaitReverseTriggerSurvivesRegularPingsWst(t *testing.T) {
	const interval = 30 * time.Millisecond
	a, b := net.Pipe()
	defer func() { _ = a.Close() }()
	defer func() { _ = b.Close() }()
	go func() { _, _ = io.Copy(io.Discard, b) }() // drain pongs
	go func() {
		for range 15 {
			time.Sleep(interval)
			if _, err := b.Write([]byte{0x80 | wst.PingMessage, 0}); err != nil {
				return
			}
		}
		_, _ = b.Write([]byte{0x80 | wst.BinaryMessage, 4, 'w', 'a', 'k', 'e'})
		time.Sleep(8 * interval)
		_, _ = b.Write([]byte{0x80 | wst.BinaryMessage, 6, 's', 'e', 'c', 'o', 'n', 'd'})
	}()

	conn := wst.NewConn(a, false)
	ts := &tunnelStream{ws: conn, r: &http.Response{Header: http.Header{
		"X-Wstunnel-Reverse-Wake": []string{"1"},
		"X-Wstunnel-Reverse-Ping": []string{"30"},
	}}}
	data, lazy, err := (&Client{}).awaitReverseTrigger(ts, false)
	if err != nil || !lazy || string(data) != "wake" {
		t.Fatalf("got data=%q lazy=%v err=%v, want the wake frame", data, lazy, err)
	}
	if _, p, err := conn.ReadMessage(); err != nil || string(p) != "second" {
		t.Fatalf("read after the parked phase: %q, %v", p, err)
	}
}

// A reverse connection dialed eagerly (the server sent no wake-up header) may be
// parked by a legacy server that never reads it, so the client only pings and
// does not expire it for silence. One the server woke up is enforced.
func TestStartPipeModeEnforcesSilenceOnlyWhenAsked(t *testing.T) {
	run := func(enforce bool) (ended bool) {
		a, b := net.Pipe()
		defer func() { _ = a.Close() }()
		go func() { _, _ = io.Copy(io.Discard, b) }() // reads pings, never answers
		local, far := net.Pipe()
		defer func() { _ = far.Close() }()
		c := &Client{Config: Config{PingFrequency: 20 * time.Millisecond}}
		done := make(chan struct{})
		go func() {
			c.startPipeMode(local, &tunnelStream{ws: wst.NewConn(a, false)}, enforce)
			close(done)
		}()
		select {
		case <-done:
			return true
		case <-time.After(500 * time.Millisecond):
			_ = b.Close()
			<-done
			return false
		}
	}
	if !run(true) {
		t.Error("an enforced pipe stayed open against a server silent for many ping intervals")
	}
	if run(false) {
		t.Error("a ping-only pipe expired a silent server; legacy servers never answer pings on a parked connection")
	}
}

// A SOCKS5 client that connects and says nothing must not hold its goroutine
// and descriptor forever (Rust #515).
func TestSocks5HandshakeIsBounded(t *testing.T) {
	old := socks5HandshakeTimeout
	socks5HandshakeTimeout = 100 * time.Millisecond
	t.Cleanup(func() { socks5HandshakeTimeout = old })

	server, client := net.Pipe()
	defer func() { _ = server.Close() }()
	defer func() { _ = client.Close() }() // never writes a greeting

	done := make(chan error, 1)
	go func() {
		_, _, _, err := (&Client{}).handleSocks5Bounded(server, nil)
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("a silent SOCKS5 client completed the handshake")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("handshake with a silent SOCKS5 client was not bounded")
	}
}

// A reverse UDP client always waits for the first datagram, even when the server
// sent no wake-up header (a Rust server, or any server over HTTP/2). That
// datagram is the trigger and is handed back to be forwarded to the target.
func TestAwaitReverseTriggerForUDPWaitsWithoutAHeader(t *testing.T) {
	t.Run("gorilla", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ws, err := (&websocket.Upgrader{}).Upgrade(w, r, nil)
			if err != nil {
				return
			}
			defer func() { _ = ws.Close() }()
			time.Sleep(50 * time.Millisecond)
			_ = ws.WriteMessage(websocket.BinaryMessage, []byte("datagram"))
			time.Sleep(300 * time.Millisecond)
		}))
		defer srv.Close()
		ws, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(srv.URL, "http"), nil)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = ws.Close() }()

		ts := &tunnelStream{gorilla: ws, r: &http.Response{Header: http.Header{}}}
		data, lazy, err := (&Client{}).awaitReverseTrigger(ts, true)
		if err != nil || !lazy || string(data) != "datagram" {
			t.Fatalf("got data=%q lazy=%v err=%v", data, lazy, err)
		}
		// Not for TCP: without the header the client dials eagerly.
		if _, lazy, _ := (&Client{}).awaitReverseTrigger(ts, false); lazy {
			t.Fatal("a TCP tunnel waited without a wake-up header")
		}
	})

	t.Run("http2 stream", func(t *testing.T) {
		a, b := net.Pipe()
		defer func() { _ = a.Close() }()
		defer func() { _ = b.Close() }()
		go func() { _, _ = b.Write([]byte("datagram")) }()
		ts := &tunnelStream{h2: a}
		data, lazy, err := (&Client{}).awaitReverseTrigger(ts, true)
		if err != nil || !lazy || string(data) != "datagram" {
			t.Fatalf("got data=%q lazy=%v err=%v", data, lazy, err)
		}
	})
}

func TestParseTargetCookie(t *testing.T) {
	sign := func(c protocol.JwtTunnelConfig) string {
		s, err := jwt.NewWithClaims(jwt.SigningMethodHS256, c).SignedString([]byte("any"))
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	tcp := protocol.LocalProtocol{Tcp: &protocol.TcpProtocol{}}

	host, port, proto, ok := parseTargetCookie(sign(protocol.JwtTunnelConfig{Remote: "example.org", Port: 443, Protocol: tcp}))
	if !ok || host != "example.org" || port != 443 || proto.Tcp == nil {
		t.Errorf("domain: %q %d %+v %v", host, port, proto, ok)
	}
	// Rust brackets an IPv6 host; net.Dial wants it bare.
	host, _, _, ok = parseTargetCookie(sign(protocol.JwtTunnelConfig{Remote: "[2001:db8::1]", Port: 80, Protocol: tcp}))
	if !ok || host != "2001:db8::1" {
		t.Errorf("ipv6: %q %v", host, ok)
	}
	// A UDP target (SOCKS5 UDP associate on a Rust server).
	_, _, proto, ok = parseTargetCookie(sign(protocol.JwtTunnelConfig{Remote: "10.0.0.1", Port: 53, Protocol: protocol.LocalProtocol{Udp: &protocol.UdpProtocol{}}}))
	if !ok || proto.Udp == nil {
		t.Errorf("udp: %+v %v", proto, ok)
	}
	for _, bad := range []string{
		"", "not a jwt",
		sign(protocol.JwtTunnelConfig{Port: 1}),
		sign(protocol.JwtTunnelConfig{Remote: "example.org"}),
		sign(protocol.JwtTunnelConfig{Remote: "example.org", Port: 80, Protocol: protocol.LocalProtocol{Socks5: &protocol.Socks5Protocol{}}}),
		sign(protocol.JwtTunnelConfig{Remote: "example.org", Port: 80, Protocol: protocol.LocalProtocol{Tcp: &protocol.TcpProtocol{}, Udp: &protocol.UdpProtocol{}}}),
	} {
		if _, _, _, ok := parseTargetCookie(bad); ok {
			t.Errorf("%q was accepted as a target", bad)
		}
	}
}

func TestReverseSocks5ConfigAndTimeouts(t *testing.T) {
	ltr, err := ParseTunnelArg("socks5://127.0.0.1:1080?login=admin&password=secret&timeout_sec=5", true)
	if err != nil {
		t.Fatal(err)
	}
	s := ltr.Protocol.ReverseSocks5
	if s == nil || s.Credentials == nil || s.Credentials.Username != "admin" || s.Credentials.Password != "secret" || s.Timeout == nil || s.Timeout.Secs != 5 {
		t.Fatalf("reverse socks5 parsed as %+v", ltr.Protocol)
	}
	if ltr.Local != "127.0.0.1:1080" {
		t.Errorf("local = %q, want the address the server listens on", ltr.Local)
	}

	if got := replyTimeout(ltr.Protocol); got != reverseReplyTimeout {
		t.Errorf("a reverse SOCKS5 request waits %v for its reply, want %v", got, reverseReplyTimeout)
	}
	// A Rust server holds the reply of every reverse tunnel until a visitor comes.
	for name, p := range map[string]protocol.LocalProtocol{
		"TCP": {ReverseTcp: &struct{}{}},
		"UDP": {ReverseUdp: &protocol.ReverseUdpProtocol{}},
	} {
		if got := replyTimeout(p); got != reverseReplyTimeout {
			t.Errorf("a reverse %s request waits %v for its reply, want %v", name, got, reverseReplyTimeout)
		}
	}
	if got := replyTimeout(protocol.LocalProtocol{Tcp: &protocol.TcpProtocol{}}); got >= reverseReplyTimeout {
		t.Errorf("a forward request waits %v, want it short: its reply is immediate", got)
	}

	for _, err := range []error{context.DeadlineExceeded, os.ErrDeadlineExceeded, fmt.Errorf("failed to dial: %w", &net.OpError{Err: os.ErrDeadlineExceeded})} {
		if !isTimeout(err) {
			t.Errorf("%v not recognised as a timeout", err)
		}
	}
	if isTimeout(errors.New("connection refused")) {
		t.Error("an ordinary error was taken for a timeout")
	}
}

// A reverse SOCKS5 request over HTTP/2 is answered only when a visitor asks for
// something. The reply timeout must cut a request that gets no answer, and must
// leave a tunnel alone once the answer has come.
func TestHTTP2ReplyTimeoutOfAHeldRequest(t *testing.T) {
	old := reverseReplyTimeout
	reverseReplyTimeout = 300 * time.Millisecond
	t.Cleanup(func() { reverseReplyTimeout = old })

	released := make(chan struct{})
	cancelled := make(chan struct{})
	protocols := new(http.Protocols)
	protocols.SetHTTP1(true)
	protocols.SetUnencryptedHTTP2(true)
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-released: // answer: headers now, then data well after the timeout
			w.WriteHeader(http.StatusOK)
			w.(http.Flusher).Flush()
			time.Sleep(700 * time.Millisecond)
			_, _ = w.Write([]byte("late data"))
			w.(http.Flusher).Flush()
			time.Sleep(200 * time.Millisecond)
		case <-r.Context().Done():
			close(cancelled)
		}
	}))
	srv.Config.Protocols = protocols
	srv.Start()
	defer srv.Close()

	c := NewClient(Config{ServerURL: srv.URL, PathPrefix: "v1"})
	proto := protocol.LocalProtocol{ReverseSocks5: &protocol.ReverseSocks5Protocol{}}

	// No answer: a timeout error, well before the 30 seconds, and the server
	// sees the request cancelled.
	start := time.Now()
	_, _, err := c.connectToHttp2(proto, "127.0.0.1", 1080)
	if err == nil || !isTimeout(err) {
		t.Fatalf("got %v, want a timeout", err)
	}
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Fatalf("the reply timeout took %v", elapsed)
	}
	select {
	case <-cancelled:
	case <-time.After(2 * time.Second):
		t.Fatal("the server never saw the abandoned request cancelled")
	}

	// An answer: the tunnel outlives the timeout and still carries data.
	close(released)
	rwc, _, err := c.connectToHttp2(proto, "127.0.0.1", 1080)
	if err != nil {
		t.Fatalf("answered request failed: %v", err)
	}
	defer func() { _ = rwc.Close() }()
	buf := make([]byte, len("late data"))
	if _, err := io.ReadFull(rwc, buf); err != nil || string(buf) != "late data" {
		t.Fatalf("data after the reply timeout: %q, %v", buf, err)
	}
}

// Each HTTP/2 tunnel has a transport of its own, so its connection must go away
// with it. A tunnel that ended, or a held request that was cancelled, must not
// leave an idle connection open on both peers.
func TestHTTP2TunnelConnectionIsClosedWithTheTunnel(t *testing.T) {
	old := reverseReplyTimeout
	reverseReplyTimeout = 300 * time.Millisecond
	t.Cleanup(func() { reverseReplyTimeout = old })

	var open atomic.Int32
	answer := make(chan struct{})
	protocols := new(http.Protocols)
	protocols.SetHTTP1(true)
	protocols.SetUnencryptedHTTP2(true)
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-answer:
			w.WriteHeader(http.StatusOK)
			w.(http.Flusher).Flush()
			_, _ = io.Copy(io.Discard, r.Body) // until the client ends the tunnel
		case <-r.Context().Done():
		}
	}))
	srv.Config.Protocols = protocols
	srv.Config.ConnState = func(_ net.Conn, s http.ConnState) {
		switch s {
		case http.StateNew:
			open.Add(1)
		case http.StateClosed, http.StateHijacked:
			open.Add(-1)
		}
	}
	srv.Start()
	defer srv.Close()

	waitFor := func(what string, want int32) {
		t.Helper()
		deadline := time.Now().Add(3 * time.Second)
		for time.Now().Before(deadline) {
			if open.Load() == want {
				return
			}
			time.Sleep(20 * time.Millisecond)
		}
		t.Fatalf("%s: %d connections open on the server, want %d", what, open.Load(), want)
	}

	c := NewClient(Config{ServerURL: srv.URL, PathPrefix: "v1"})
	held := protocol.LocalProtocol{ReverseSocks5: &protocol.ReverseSocks5Protocol{}}

	// A held request that times out takes its connection with it.
	if _, _, err := c.connectToHttp2(held, "127.0.0.1", 1080); err == nil {
		t.Fatal("an unanswered request succeeded")
	}
	waitFor("after a held request timed out", 0)

	// An established tunnel does too, once it is closed.
	close(answer)
	rwc, _, err := c.connectToHttp2(held, "127.0.0.1", 1080)
	if err != nil {
		t.Fatal(err)
	}
	waitFor("while the tunnel is up", 1)
	_ = rwc.Close()
	waitFor("after the tunnel closed", 0)
}

// A server that answers a reverse SOCKS5 request with a target that cannot be
// read is failing it. The client must back off, not dial the placeholder address
// of the tunnel and ask again at once.
func TestReverseSocks5BacksOffOnAnUnreadableTarget(t *testing.T) {
	var requests atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		ws, err := (&websocket.Upgrader{Subprotocols: []string{"v1"}}).Upgrade(w, r, http.Header{"Cookie": []string{"this is not a jwt"}})
		if err != nil {
			return
		}
		_ = ws.Close()
	}))
	defer srv.Close()

	c := NewClient(Config{ServerURL: "ws" + strings.TrimPrefix(srv.URL, "http"), PathPrefix: "v1", WebsocketProtocol: "ws"})
	ltr, err := ParseTunnelArg("socks5://127.0.0.1:1080", true)
	if err != nil {
		t.Fatal(err)
	}
	go c.StartReverseTunnel(ltr)

	time.Sleep(1500 * time.Millisecond)
	// Without a backoff the loop spins, hundreds of requests a second.
	if n := requests.Load(); n > 4 {
		t.Fatalf("%d requests in 1.5s for replies with an unreadable target: the client does not back off", n)
	}
	if requests.Load() == 0 {
		t.Fatal("the client never made a request")
	}
}

// A server that takes a reverse UDP request and drops the connection at once (it
// could not bind the listener) is refusing it. The client must back off, not
// ask again straight away.
func TestReverseUDPBacksOffWhenTheServerDropsTheConnectionAtOnce(t *testing.T) {
	var requests atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		ws, err := (&websocket.Upgrader{Subprotocols: []string{"v1"}}).Upgrade(w, r, nil)
		if err != nil {
			return
		}
		_ = ws.Close() // accepted, then dropped
	}))
	defer srv.Close()

	c := NewClient(Config{ServerURL: "ws" + strings.TrimPrefix(srv.URL, "http"), PathPrefix: "v1", WebsocketProtocol: "ws"})
	ltr, err := ParseTunnelArg("udp://127.0.0.1:9053:127.0.0.1:53", true)
	if err != nil {
		t.Fatal(err)
	}
	go c.StartReverseTunnel(ltr)

	time.Sleep(1500 * time.Millisecond)
	if n := requests.Load(); n > 4 {
		t.Fatalf("%d requests in 1.5s for connections dropped at once: the client does not back off", n)
	}
	if requests.Load() == 0 {
		t.Fatal("the client never made a request")
	}
}
