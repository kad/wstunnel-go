package client

import (
	"context"
	"errors"
	"github.com/kad/wstunnel-go/pkg/protocol"
	"github.com/kad/wstunnel-go/pkg/server"
	"github.com/kad/wstunnel-go/pkg/wst"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// A UDP ASSOCIATE request is recognised, not refused or treated as a target.
func TestHandleSocks5RecognisesUDPAssociate(t *testing.T) {
	server, client := net.Pipe()
	defer func() { _ = server.Close(); _ = client.Close() }()
	go func() {
		_, _ = client.Write([]byte{5, 1, 0})
		_, _ = io.ReadFull(client, make([]byte, 2))
		_, _ = client.Write([]byte{5, 3, 0, 1, 0, 0, 0, 0, 0, 0})
	}()
	_ = server.SetDeadline(time.Now().Add(3 * time.Second))
	_, _, _, err := (&Client{}).handleSocks5(server, nil)
	if !errors.Is(err, errSocks5UDPAssociate) {
		t.Fatalf("err = %v, want the UDP ASSOCIATE marker", err)
	}
}

// A command that is neither CONNECT nor UDP ASSOCIATE is answered "command not
// supported" instead of leaving the visitor waiting.
func TestHandleSocks5AnswersUnsupportedCommand(t *testing.T) {
	server, client := net.Pipe()
	defer func() { _ = server.Close(); _ = client.Close() }()
	got := make(chan []byte, 1)
	go func() {
		_, _ = client.Write([]byte{5, 1, 0})
		_, _ = io.ReadFull(client, make([]byte, 2))
		_, _ = client.Write([]byte{5, 2, 0, 1}) // BIND
		reply := make([]byte, 10)
		_, _ = io.ReadFull(client, reply)
		got <- reply
	}()
	_ = server.SetDeadline(time.Now().Add(3 * time.Second))
	if _, _, _, err := (&Client{}).handleSocks5(server, nil); err == nil {
		t.Fatal("BIND was accepted")
	}
	select {
	case reply := <-got:
		if reply[1] != 0x07 {
			t.Fatalf("reply %v, want command not supported", reply)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("the visitor got no reply")
	}
}

func TestSocks5UDPReplyAddrUsesTCPAddressForUnspecifiedRelay(t *testing.T) {
	server, client := net.Pipe()
	defer func() { _ = server.Close(); _ = client.Close() }()
	out := make(chan []byte, 1)
	go func() {
		b := make([]byte, 10)
		_, _ = io.ReadFull(client, b)
		out <- b
	}()
	// net.Pipe has no TCP addresses, so the unspecified address is sent as is.
	if err := socks5UDPReplyAddr(server, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1080}); err != nil {
		t.Fatal(err)
	}
	b := <-out
	if b[1] != 0 || b[3] != 1 || net.IP(b[4:8]).String() != "127.0.0.1" || int(b[8])<<8|int(b[9]) != 1080 {
		t.Fatalf("reply %v", b)
	}
}

// A server that accepts the connection and never answers the upgrade, so opening
// a tunnel hangs.
func blackholeServer(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			t.Cleanup(func() { _ = c.Close() })
		}
	}()
	return ln.Addr().String()
}

// A session whose tunnel is slow to open expires on its own timeout, and does not
// keep its slot for as long as the dial lasts.
func TestSocks5UDPSessionExpiresWhileTunnelIsOpening(t *testing.T) {
	c := NewClient(Config{ServerURL: "ws://" + blackholeServer(t), PathPrefix: "v1"})
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	r := &socks5Relay{sessions: make(map[string]*socks5UDPSession)}
	go c.serveSocks5UDPRelay(r, pc, 300*time.Millisecond)

	visitor, err := net.DialUDP("udp", nil, pc.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = visitor.Close() }()
	_, _ = visitor.Write(append(protocol.Socks5UDPHeader("10.9.8.7", 53), "query"...))

	deadline := time.Now().Add(2 * time.Second)
	for r.count() == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if r.count() != 1 {
		t.Fatalf("%d sessions after a datagram, want 1", r.count())
	}
	// The dial would hang for seconds; the session must be gone well before.
	deadline = time.Now().Add(2 * time.Second)
	for r.count() != 0 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if r.count() != 0 {
		t.Fatal("the session outlived its timeout while its tunnel was opening")
	}
	_ = pc.Close()
}

// Queued payload is capped across the sessions of a relay, and given back when a
// session ends.
func TestSocks5UDPQueuedBytesAreBudgeted(t *testing.T) {
	old := maxSocks5UDPQueuedBytes
	maxSocks5UDPQueuedBytes = 100
	t.Cleanup(func() { maxSocks5UDPQueuedBytes = old })

	var budget udpBudget
	newSession := func() *socks5UDPSession {
		return &socks5UDPSession{out: make(chan []byte, socks5UDPQueue), budget: &budget, closed: make(chan struct{}), last: time.Now()}
	}
	a, b := newSession(), newSession()
	a.enqueue(make([]byte, 60))
	b.enqueue(make([]byte, 60)) // over the relay's budget
	if len(b.out) != 0 || budget.used.Load() != 60 {
		t.Fatalf("b queued %d datagrams, %d bytes used; want b's dropped", len(b.out), budget.used.Load())
	}
	a.close()
	if got := budget.used.Load(); got != 0 {
		t.Fatalf("%d bytes still reserved after the session ended", got)
	}
	a.enqueue(make([]byte, 10)) // ended: not queued
	if got := budget.used.Load(); got != 0 {
		t.Fatalf("%d bytes reserved for an ended session", got)
	}
}

// Opening a tunnel stops when its context ends, on every transport that is a
// connection to a server that never answers: before the fix an expired session
// left the request and its goroutines behind.
func TestConnectToTransportStopsWhenContextEnds(t *testing.T) {
	addr := blackholeServer(t)
	cases := map[string]Config{
		"websocket":     {ServerURL: "ws://" + addr, PathPrefix: "v1"},
		"websocket-rfc": {ServerURL: "ws://" + addr, PathPrefix: "v1", WebsocketProtocol: "ws"},
		"http2":         {ServerURL: "http://" + addr, PathPrefix: "v1"},
	}
	for name, cfg := range cases {
		t.Run(name, func(t *testing.T) {
			c := NewClient(cfg)
			ctx, cancel := context.WithCancel(context.Background())
			done := make(chan *tunnelStream, 1)
			go func() {
				done <- c.connectToTransportContext(ctx, protocol.LocalProtocol{Udp: &protocol.UdpProtocol{}}, "10.9.8.7", 53)
			}()
			time.Sleep(200 * time.Millisecond)
			cancel()
			select {
			case ts := <-done:
				if ts.err == nil {
					ts.Close()
					t.Fatal("a tunnel opened against a server that never answers")
				}
			case <-time.After(3 * time.Second):
				t.Fatal("opening the tunnel did not stop when its context ended")
			}
		})
	}
}

// A caller of the shared WebTransport dial stops waiting when its context ends,
// without aborting the dial for the others.
func TestWebTransportConnectStopsWaitingWhenContextEnds(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = pc.Close() }() // takes packets, answers nothing
	c := NewClient(Config{ServerURL: "wt://" + pc.LocalAddr().String(), PathPrefix: "v1"})

	for i := range 2 { // the second caller waits for the dial the first started
		ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
		done := make(chan error, 1)
		go func() {
			_, _, err := c.wtClient.Connect(ctx, protocol.LocalProtocol{Udp: &protocol.UdpProtocol{}}, "10.9.8.7", 53)
			done <- err
		}()
		select {
		case err := <-done:
			if err == nil || !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("caller %d: err = %v, want its context's deadline", i, err)
			}
		case <-time.After(3 * time.Second):
			t.Fatalf("caller %d kept waiting after its context ended", i)
		}
		cancel()
	}
}

// A reverse request over WebTransport that no visitor answers stops waiting when
// its context ends, instead of holding the stream until the reply timeout.
func TestWebTransportReverseRequestStopsWhenContextEnds(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	srv := server.NewServer(server.Config{ListenAddr: "wt://" + addr, PathPrefix: "v1", WebsocketProtocol: "rust"})
	go func() { _ = srv.Start() }()
	t.Cleanup(func() { _ = srv.Close() })
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if c, err := net.DialTimeout("tcp", addr, 100*time.Millisecond); err == nil {
			_ = c.Close()
			break
		}
		time.Sleep(50 * time.Millisecond)
	}

	c := NewClient(Config{ServerURL: "wt://" + addr, PathPrefix: "v1"})
	ctx, cancel := context.WithTimeout(context.Background(), 700*time.Millisecond)
	defer cancel()
	proto := protocol.LocalProtocol{ReverseSocks5: &protocol.ReverseSocks5Protocol{}}
	done := make(chan error, 1)
	go func() {
		_, _, err := c.wtClient.Connect(ctx, proto, "127.0.0.1", 0)
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil || !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("err = %v, want the context's deadline", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the request kept waiting for a visitor after its context ended")
	}
}

// A relay that asks for credentials serves only senders with an authenticated
// association: no tunnel is opened for anyone else.
func TestSocks5UDPRelayNeedsAnAssociationWithCredentials(t *testing.T) {
	c := NewClient(Config{ServerURL: "ws://" + blackholeServer(t), PathPrefix: "v1"})
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	assoc := &protocol.UDPAssociations{}
	r := &socks5Relay{assoc: assoc, sessions: make(map[string]*socks5UDPSession)}
	go c.serveSocks5UDPRelay(r, pc, 30*time.Second)
	defer func() { _ = pc.Close() }()

	visitor, err := net.DialUDP("udp", nil, pc.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = visitor.Close() }()
	datagram := append(protocol.Socks5UDPHeader("10.9.8.7", 53), "query"...)

	_, _ = visitor.Write(datagram)
	time.Sleep(400 * time.Millisecond)
	if r.count() != 0 {
		t.Fatal("a sender without an association got a tunnel")
	}

	release := assoc.Add(net.ParseIP("127.0.0.1"))
	_, _ = visitor.Write(datagram)
	deadline := time.Now().Add(2 * time.Second)
	for r.count() == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if r.count() != 1 {
		t.Fatal("an authenticated sender was not served")
	}
	release()
}

// A CONNECT through an upstream proxy that never answers stops when the context
// ends instead of waiting out the proxy handshake.
func TestDialViaHTTPProxyStopsWhenContextEnds(t *testing.T) {
	c := NewClient(Config{ServerURL: "ws://example.invalid:80"})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := c.dialViaHTTPProxy(ctx, &net.Dialer{}, "tcp", "example.invalid:80", "http://"+blackholeServer(t))
		done <- err
	}()
	time.Sleep(200 * time.Millisecond)
	cancel()
	select {
	case err := <-done:
		if err == nil || !errors.Is(err, context.Canceled) {
			t.Fatalf("err = %v, want the context's cancellation", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("the CONNECT kept waiting for the proxy after its context ended")
	}
}

// A WebSocket tunnel whose server stops answering ends the session, so the next
// datagram opens a new one, even while the sender keeps sending.
func TestSocks5UDPSessionEndsWhenTheServerGoesSilent(t *testing.T) {
	hold := make(chan struct{})
	t.Cleanup(func() { close(hold) })
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u := wst.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
		c, err := u.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		<-hold // upgraded, then never read: no pong, no frame
		_ = c.Close()
	}))
	t.Cleanup(srv.Close)

	c := NewClient(Config{ServerURL: "ws://" + srv.Listener.Addr().String(), PathPrefix: "v1", PingFrequency: 100 * time.Millisecond})
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	r := &socks5Relay{sessions: make(map[string]*socks5UDPSession)}
	go c.serveSocks5UDPRelay(r, pc, time.Minute)
	defer func() { _ = pc.Close() }()

	visitor, err := net.DialUDP("udp", nil, pc.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = visitor.Close() }()
	datagram := append(protocol.Socks5UDPHeader("10.9.8.7", 53), "query"...)
	_, _ = visitor.Write(datagram)
	deadline := time.Now().Add(2 * time.Second)
	for r.count() == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if r.count() != 1 {
		t.Fatal("no session was opened")
	}
	// Keep sending while the server says nothing: three intervals of silence end it.
	deadline = time.Now().Add(3 * time.Second)
	for r.count() != 0 && time.Now().Before(deadline) {
		time.Sleep(50 * time.Millisecond)
	}
	if r.count() != 0 {
		t.Fatal("the session stayed on a tunnel whose server had gone silent")
	}
}
