package server

import (
	"bytes"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/kad/wstunnel-go/pkg/protocol"
	"github.com/kad/wstunnel-go/pkg/wst"
)

// socks5Visitor writes a SOCKS5 exchange to one end of a pipe and returns what
// readSocks5Request made of it.
func runSocks5Request(t *testing.T, creds *protocol.Credentials, script func(c net.Conn)) (string, uint16, error) {
	t.Helper()
	server, client := net.Pipe()
	defer func() { _ = server.Close() }()
	defer func() { _ = client.Close() }()
	go script(client)
	type result struct {
		host string
		port uint16
		err  error
	}
	res := make(chan result, 1)
	go func() {
		h, p, err := readSocks5Request(server, creds)
		res <- result{h, p, err}
	}()
	select {
	case r := <-res:
		return r.host, r.port, r.err
	case <-time.After(3 * time.Second):
		t.Fatal("readSocks5Request did not return")
		return "", 0, nil
	}
}

func drain(c net.Conn, n int) { // read n bytes of the server's replies
	buf := make([]byte, n)
	_, _ = c.Read(buf)
}

func TestReadSocks5RequestAddressTypes(t *testing.T) {
	cases := []struct {
		name     string
		request  []byte
		wantHost string
		wantPort uint16
	}{
		{"ipv4", []byte{5, 1, 0, 1, 10, 0, 0, 7, 0x1F, 0x90}, "10.0.0.7", 8080},
		{"domain", append([]byte{5, 1, 0, 3, 11}, append([]byte("example.org"), 0x01, 0xBB)...), "example.org", 443},
		{"ipv6", append([]byte{5, 1, 0, 4}, append(net.ParseIP("2001:db8::1").To16(), 0x00, 0x50)...), "2001:db8::1", 80},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			host, port, err := runSocks5Request(t, nil, func(c net.Conn) {
				_, _ = c.Write([]byte{5, 1, 0})
				drain(c, 2)
				_, _ = c.Write(tc.request)
			})
			if err != nil || host != tc.wantHost || port != tc.wantPort {
				t.Fatalf("got %q:%d err=%v, want %q:%d", host, port, err, tc.wantHost, tc.wantPort)
			}
		})
	}
}

func TestReadSocks5RequestRejectsUnsupportedCommand(t *testing.T) {
	var reply []byte
	_, _, err := runSocks5Request(t, nil, func(c net.Conn) {
		_, _ = c.Write([]byte{5, 1, 0})
		drain(c, 2)
		_, _ = c.Write([]byte{5, 3, 0, 1}) // UDP ASSOCIATE; the rest is never read (the pipe is unbuffered)
		reply = make([]byte, 10)
		_, _ = c.Read(reply)
	})
	if err == nil {
		t.Fatal("UDP ASSOCIATE was accepted")
	}
	if len(reply) < 2 || reply[1] != socks5CommandNotSupported {
		t.Fatalf("reply %v, want command-not-supported", reply)
	}
}

func TestReadSocks5RequestRejectsUnusableTargets(t *testing.T) {
	cases := map[string][]byte{
		"port zero":    {5, 1, 0, 1, 10, 0, 0, 7, 0, 0},
		"empty domain": {5, 1, 0, 3, 0, 0x01, 0xBB},
	}
	for name, request := range cases {
		t.Run(name, func(t *testing.T) {
			var reply []byte
			_, _, err := runSocks5Request(t, nil, func(c net.Conn) {
				_, _ = c.Write([]byte{5, 1, 0})
				drain(c, 2)
				_, _ = c.Write(request)
				reply = make([]byte, 10)
				_, _ = io.ReadFull(c, reply)
			})
			if err == nil {
				t.Fatal("the target was accepted")
			}
			if len(reply) < 2 || reply[1] != socks5GeneralFailure {
				t.Fatalf("reply %v, want general failure", reply)
			}
		})
	}
}

func TestReadSocks5RequestPasswordAuth(t *testing.T) {
	creds := &protocol.Credentials{Username: "admin", Password: "secret"}
	auth := func(user, pass string) []byte {
		b := []byte{1, byte(len(user))}
		b = append(b, user...)
		b = append(b, byte(len(pass)))
		return append(b, pass...)
	}

	t.Run("accepted", func(t *testing.T) {
		host, port, err := runSocks5Request(t, creds, func(c net.Conn) {
			_, _ = c.Write([]byte{5, 1, 2})
			drain(c, 2)
			_, _ = c.Write(auth("admin", "secret"))
			drain(c, 2)
			_, _ = c.Write([]byte{5, 1, 0, 1, 1, 1, 1, 1, 0, 80})
		})
		if err != nil || host != "1.1.1.1" || port != 80 {
			t.Fatalf("got %q:%d err=%v", host, port, err)
		}
	})
	t.Run("wrong password", func(t *testing.T) {
		var status []byte
		_, _, err := runSocks5Request(t, creds, func(c net.Conn) {
			_, _ = c.Write([]byte{5, 1, 2})
			drain(c, 2)
			_, _ = c.Write(auth("admin", "nope"))
			status = make([]byte, 2)
			_, _ = c.Read(status)
		})
		if err == nil {
			t.Fatal("wrong password accepted")
		}
		if !bytes.Equal(status, []byte{1, 1}) {
			t.Fatalf("auth status %v, want failure", status)
		}
	})
	t.Run("no password method offered", func(t *testing.T) {
		_, _, err := runSocks5Request(t, creds, func(c net.Conn) {
			_, _ = c.Write([]byte{5, 1, 0}) // only "no authentication"
			drain(c, 2)
		})
		if err == nil {
			t.Fatal("a client that offered no password method was accepted")
		}
	})
}

func TestTargetCookieCarriesTheTarget(t *testing.T) {
	m := NewReverseTunnelManager(0, time.Minute).withCookieSigner(cookieSigner("s3cret"))
	t.Cleanup(m.Close)

	for _, tc := range []struct{ host, wantRemote string }{
		{"example.org", "example.org"},
		{"10.1.2.3", "10.1.2.3"},
		{"2001:db8::1", "[2001:db8::1]"}, // Rust parses the host as a URL host
	} {
		tok, err := m.targetCookie(tc.host, 8443)
		if err != nil {
			t.Fatal(err)
		}
		claims := &protocol.JwtTunnelConfig{}
		if _, _, err := jwt.NewParser().ParseUnverified(tok, claims); err != nil {
			t.Fatal(err)
		}
		if claims.Remote != tc.wantRemote || claims.Port != 8443 || claims.Protocol.Tcp == nil {
			t.Errorf("%s: claims = %+v, want TCP to %s:8443", tc.host, claims, tc.wantRemote)
		}
	}
}

// A held request whose client goes away (or gives up after its reply timeout and
// asks again) must leave the pool, instead of waiting for a visitor that would
// then be handed a dead request.
func TestHeldRequestLeavesThePoolWhenItsClientGoesAway(t *testing.T) {
	mgr := NewReverseTunnelManager(0, time.Minute).withCookieSigner(cookieSigner(""))
	t.Cleanup(mgr.Close)
	claims := &protocol.JwtTunnelConfig{
		ID:       "held",
		Remote:   "127.0.0.1",
		Protocol: protocol.LocalProtocol{ReverseSocks5: &protocol.ReverseSocks5Protocol{}},
	}
	gone := make(chan struct{})
	returned := make(chan struct{})
	go func() {
		_ = mgr.HandleDynamicClient(claims, lazyUpgrade{stream: func(http.Header) (io.ReadWriteCloser, error) { return nil, nil }}, gone)
		close(returned)
	}()

	tl := waitForListener(t, mgr)
	waitForPoolSize(t, tl, 1)
	close(gone)
	select {
	case <-returned:
	case <-time.After(3 * time.Second):
		t.Fatal("a held request stayed after its client went away")
	}
	waitForPoolSize(t, tl, 0)
}

func waitForListener(t *testing.T, mgr *ReverseTunnelManager) *tunnelListener {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		mgr.mu.Lock()
		for _, tl := range mgr.listeners {
			mgr.mu.Unlock()
			return tl
		}
		mgr.mu.Unlock()
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("no reverse listener appeared")
	return nil
}

func waitForPoolSize(t *testing.T, tl *tunnelListener, n int) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		tl.queueMu.Lock()
		size := 0
		for _, w := range tl.waiting {
			select {
			case <-w.done:
			default:
				size++
			}
		}
		tl.queueMu.Unlock()
		if size == n {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("pool did not reach %d waiting requests", n)
}

// A client that comes back with other credentials must not get the listener it
// left behind: that one would keep serving with the old settings, or none.
func TestListenerIsReplacedWhenTheClientsSettingsChange(t *testing.T) {
	mgr := NewReverseTunnelManager(0, time.Minute)
	t.Cleanup(mgr.Close)
	first := &protocol.JwtTunnelConfig{
		ID: "a", Remote: "127.0.0.1", Port: 0,
		Protocol: protocol.LocalProtocol{ReverseSocks5: &protocol.ReverseSocks5Protocol{}},
	}
	tl1, _, err := mgr.getOrCreateListener(first)
	if err != nil {
		t.Fatal(err)
	}

	// Same settings: the same listener.
	again, _, err := mgr.getOrCreateListener(&protocol.JwtTunnelConfig{
		ID: "b", Remote: first.Remote, Port: first.Port,
		Protocol: protocol.LocalProtocol{ReverseSocks5: &protocol.ReverseSocks5Protocol{}},
	})
	if err != nil || again != tl1 {
		t.Fatalf("same settings should reuse the listener: %v, same=%v", err, again == tl1)
	}

	// A password is added: the idle listener is replaced and requires it.
	withAuth := &protocol.JwtTunnelConfig{
		ID: "c", Remote: first.Remote, Port: first.Port,
		Protocol: protocol.LocalProtocol{ReverseSocks5: &protocol.ReverseSocks5Protocol{
			Credentials: &protocol.Credentials{Username: "u", Password: "p"},
		}},
	}
	tl2, _, err := mgr.getOrCreateListener(withAuth)
	if err != nil {
		t.Fatal(err)
	}
	if tl2 == tl1 || tl2.protocol.ReverseSocks5.Credentials == nil {
		t.Fatal("the listener kept its old, unauthenticated settings")
	}

	// While it is serving a visitor it is not cut off for a newcomer with other settings.
	mgr.beginIncoming(tl2)
	other := *withAuth
	other.Protocol = protocol.LocalProtocol{ReverseSocks5: &protocol.ReverseSocks5Protocol{
		Credentials: &protocol.Credentials{Username: "u", Password: "changed"},
	}}
	if _, _, err := mgr.getOrCreateListener(&other); err == nil {
		t.Fatal("a busy listener was replaced under its visitors")
	}
}

// Shutdown and an upgrade in progress must not race: a connection the upgrade
// produces after the request ended is closed, never published.
func TestFinishWaitsForAnUpgradeInProgress(t *testing.T) {
	w := &waitingConn{acquired: make(chan struct{}), done: make(chan struct{})}
	started := make(chan struct{})
	release := make(chan struct{})
	closed := make(chan struct{})
	w.lazy = func(http.Header) error {
		close(started)
		<-release
		w.h2Conn = closerFunc(func() error { close(closed); return nil })
		return nil
	}
	upgraded := make(chan error, 1)
	go func() { upgraded <- w.completeUpgrade(nil) }()
	<-started

	finished := make(chan struct{})
	go func() { w.finish(true); close(finished) }()
	select {
	case <-finished:
		t.Fatal("finish returned while an upgrade was still running")
	case <-time.After(100 * time.Millisecond):
	}
	close(release)
	if err := <-upgraded; err != nil {
		t.Fatal(err)
	}
	<-finished
	select {
	case <-closed:
	case <-time.After(2 * time.Second):
		t.Fatal("the connection the upgrade produced was not closed by finish")
	}
	if err := w.completeUpgrade(nil); !errors.Is(err, errRequestEnded) {
		t.Fatalf("an upgrade after the end returned %v, want errRequestEnded", err)
	}
}

type closerFunc func() error

func (f closerFunc) Read([]byte) (int, error)    { return 0, io.EOF }
func (f closerFunc) Write(p []byte) (int, error) { return len(p), nil }
func (f closerFunc) Close() error                { return f() }

// With the pool full, a held request waits for a place. When its client goes
// away it must leave at once, not sit in the queue until a place frees up.
func TestHeldRequestBlockedOnAFullPoolLeavesWhenItsClientGoes(t *testing.T) {
	mgr := NewReverseTunnelManager(0, time.Minute).withCookieSigner(cookieSigner(""))
	t.Cleanup(mgr.Close)
	claims := &protocol.JwtTunnelConfig{
		ID: "full", Remote: "127.0.0.1",
		Protocol: protocol.LocalProtocol{ReverseSocks5: &protocol.ReverseSocks5Protocol{}},
	}
	tl, _, err := mgr.getOrCreateListener(claims)
	if err != nil {
		t.Fatal(err)
	}
	for range tl.waitCap { // fill every place
		w := &waitingConn{acquired: make(chan struct{}), done: make(chan struct{})}
		if !mgr.enqueueWaitingConn(tl, w) {
			t.Fatal("could not fill the pool")
		}
	}

	gone := make(chan struct{})
	returned := make(chan struct{})
	go func() {
		_ = mgr.HandleDynamicClient(claims, lazyUpgrade{stream: func(http.Header) (io.ReadWriteCloser, error) { return nil, nil }}, gone)
		close(returned)
	}()
	select {
	case <-returned:
		t.Fatal("a request returned although the pool was full")
	case <-time.After(150 * time.Millisecond):
	}
	close(gone)
	select {
	case <-returned:
	case <-time.After(3 * time.Second):
		t.Fatal("a held request stayed blocked on the full pool after its client went away")
	}
}

// The client of a held stream that ends it is noticed, so its request leaves the
// pool; and stopping the watch gives the stream back untouched.
func TestWatchHeldStream(t *testing.T) {
	t.Run("client ends the stream", func(t *testing.T) {
		server, client := net.Pipe()
		defer func() { _ = server.Close() }()
		gone, stop := watchHeldStream(server)
		defer stop()
		_ = client.Close()
		select {
		case <-gone:
		case <-time.After(2 * time.Second):
			t.Fatal("the end of the stream was not noticed")
		}
	})

	t.Run("stop leaves the stream and its data alone", func(t *testing.T) {
		server, client := net.Pipe()
		defer func() { _ = server.Close() }()
		defer func() { _ = client.Close() }()
		gone, stop := watchHeldStream(server)
		stop()
		stop() // safe to repeat
		select {
		case <-gone:
			t.Fatal("stopping the watch reported the client as gone")
		default:
		}
		go func() { _, _ = client.Write([]byte("hello")) }()
		buf := make([]byte, 5)
		if _, err := io.ReadFull(server, buf); err != nil || string(buf) != "hello" {
			t.Fatalf("read after stop: %q, %v", buf, err)
		}
	})
}

// A request that cannot be held at all (the port is taken) must come back as an
// error, so the handler can answer with an HTTP error and the client backs off,
// rather than getting an empty 200 and asking again at once.
func TestHandleDynamicClientReportsListenerFailure(t *testing.T) {
	taken, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = taken.Close() }()

	mgr := NewReverseTunnelManager(0, time.Minute)
	t.Cleanup(mgr.Close)
	claims := &protocol.JwtTunnelConfig{
		ID: "busy-port", Remote: "127.0.0.1", Port: uint16(taken.Addr().(*net.TCPAddr).Port),
		Protocol: protocol.LocalProtocol{ReverseSocks5: &protocol.ReverseSocks5Protocol{}},
	}
	done := make(chan error, 1)
	go func() {
		done <- mgr.HandleDynamicClient(claims, lazyUpgrade{stream: func(http.Header) (io.ReadWriteCloser, error) { return nil, nil }}, nil)
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("a request on a port that is taken was accepted")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("the request was held although its listener could not start")
	}
}

// closeTracker reports when its connection is closed.
type closeTracker struct {
	net.Conn
	closed chan struct{}
	once   sync.Once
}

func (c *closeTracker) Close() error {
	c.once.Do(func() { close(c.closed) })
	return c.Conn.Close()
}

// The transport of a held request that was upgraded for a visitor is closed
// when the session ends: no handler is left to do it. The pipe only sends a
// WebSocket close frame, and when the client then hangs up the socket would stay
// half open for good.
func TestUpgradedSocketIsClosedWhenTheSessionEnds(t *testing.T) {
	mgr := NewReverseTunnelManager(0, time.Minute).withCookieSigner(cookieSigner(""))
	t.Cleanup(mgr.Close)
	claims := &protocol.JwtTunnelConfig{
		ID: "close-after", Remote: "127.0.0.1", Port: 0,
		Protocol: protocol.LocalProtocol{ReverseSocks5: &protocol.ReverseSocks5Protocol{}},
	}

	srvEnd, cliEnd := net.Pipe() // the tunnel's socket
	tracked := &closeTracker{Conn: srvEnd, closed: make(chan struct{})}
	returned := make(chan struct{})
	go func() {
		_ = mgr.HandleDynamicClient(claims, lazyUpgrade{wst: func(http.Header) (*wst.Conn, error) {
			return wst.NewConn(tracked, false), nil
		}}, nil)
		close(returned)
	}()
	tl := waitForListener(t, mgr)
	waitForPoolSize(t, tl, 1)

	// The client side behaves as a client does: it reads until the server's
	// close frame, then hangs up.
	go func() {
		c := wst.NewConn(cliEnd, false)
		for {
			if _, _, err := c.ReadMessage(); err != nil {
				_ = cliEnd.Close()
				return
			}
		}
	}()

	// A visitor asks for a target, then goes away.
	visitor, err := net.Dial("tcp", tl.ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	_, _ = visitor.Write([]byte{5, 1, 0})
	greeting := make([]byte, 2)
	_, _ = io.ReadFull(visitor, greeting)
	_, _ = visitor.Write([]byte{5, 1, 0, 1, 10, 0, 0, 1, 0, 80})
	reply := make([]byte, 10)
	if _, err := io.ReadFull(visitor, reply); err != nil || reply[1] != socks5Succeeded {
		t.Fatalf("SOCKS5 reply %v, %v", reply, err)
	}
	_ = visitor.Close()

	select {
	case <-tracked.closed:
	case <-time.After(3 * time.Second):
		t.Fatal("the tunnel's socket was not closed when the session ended")
	}
	select {
	case <-returned:
	case <-time.After(3 * time.Second):
		t.Fatal("the handler did not return after the session")
	}
}

// With no timeout, or a zero one, a reverse UDP peer is never expired, as in Rust.
func TestReverseUDPWithoutTimeoutNeverExpires(t *testing.T) {
	mgr := NewReverseTunnelManager(0, time.Minute)
	t.Cleanup(mgr.Close)
	tl, _, err := mgr.getOrCreateListener(reverseUDPClaims("udp-no-timeout", nil))
	if err != nil {
		t.Fatal(err)
	}
	client := parkClient(t, mgr, tl)
	peer, err := net.DialUDP("udp", nil, tl.pc.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = peer.Close() }()
	if _, err := peer.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	_ = clientsRead(t, client, "ping")

	closed := make(chan error, 1)
	go func() { _, _, err := client.ReadMessage(); closed <- err }()
	select {
	case err := <-closed:
		t.Fatalf("a peer without a timeout was ended: %v", err)
	case <-time.After(700 * time.Millisecond): // far beyond any timeout the other tests use
	}
}

// The handler of a pooled connection must outlive the visitor's pipe: an
// HTTP/2 pipe writes through the handler's response writer, which is invalid
// after the handler returns, however early the request was cancelled.
func TestHandlerWaitsForTheVisitorsPipe(t *testing.T) {
	mgr := NewReverseTunnelManager(0, time.Minute)
	t.Cleanup(mgr.Close)
	tl, _, err := mgr.getOrCreateListener(reverseUDPClaims("pipe-wait", nil))
	if err != nil {
		t.Fatal(err)
	}
	w := &waitingConn{acquired: make(chan struct{}), done: make(chan struct{})}
	if !mgr.enqueueWaitingConn(tl, w) {
		t.Fatal("could not queue")
	}
	got, ok := mgr.acquireWaitingConn(tl) // a visitor takes it: the pipe is now running
	if !ok || got != w {
		t.Fatal("the visitor did not get the connection")
	}

	returned := make(chan struct{})
	go func() { mgr.waitForUseOrTimeout(tl, w); close(returned) }()

	w.finish(true) // the request is cancelled; the pipe is still stopping
	select {
	case <-returned:
		t.Fatal("the handler returned while the visitor's pipe was still running")
	case <-time.After(150 * time.Millisecond):
	}
	w.endPipe() // the pipe has returned
	select {
	case <-returned:
	case <-time.After(2 * time.Second):
		t.Fatal("the handler did not return after the pipe ended")
	}
}

// A peer whose timeout runs out must really end, even when the client ignores
// the close frame: the transport is closed under it, so the pump blocked on the
// client is released and the peer is forgotten.
func TestExpiredUDPPeerIsReleasedFromAClientThatIgnoresTheClose(t *testing.T) {
	mgr := NewReverseTunnelManager(0, time.Minute)
	t.Cleanup(mgr.Close)
	tl, _, err := mgr.getOrCreateListener(reverseUDPClaims("udp-ignore-close", &protocol.Duration{Nanos: 150_000_000}))
	if err != nil {
		t.Fatal(err)
	}
	_ = parkClient(t, mgr, tl) // the client end is never read: it ignores everything

	peer, err := net.DialUDP("udp", nil, tl.pc.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = peer.Close() }()
	if _, err := peer.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	// The peer is counted as active until its session has fully ended.
	activeNow := func() int {
		mgr.mu.Lock()
		defer mgr.mu.Unlock()
		return tl.active
	}
	waitActive := func(want int, what string) {
		t.Helper()
		deadline := time.Now().Add(3 * time.Second)
		for activeNow() != want {
			if time.Now().After(deadline) {
				t.Fatalf("%s: active = %d, want %d", what, activeNow(), want)
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
	waitActive(1, "the peer never started a session")
	waitActive(0, "the expired peer was never released")
}

// A held WebTransport client sends nothing. If it sends a byte after all, it is
// no longer a clean held request, and it must not stay in the pool unwatched.
func TestWatchHeldStreamTreatsAnyReadAsGone(t *testing.T) {
	server, client := net.Pipe()
	defer func() { _ = server.Close() }()
	defer func() { _ = client.Close() }()
	gone, stop := watchHeldStream(server)
	defer stop()
	go func() { _, _ = client.Write([]byte{1}) }()
	select {
	case <-gone:
	case <-time.After(2 * time.Second):
		t.Fatal("a stream that received data was still treated as a held request")
	}
}

type abortableConn struct {
	closerFunc
	aborted chan struct{}
}

func (a *abortableConn) Abort() { close(a.aborted) }

// A session that is cut short interrupts a blocked HTTP/2 write; one that ends
// normally does not, so it still closes the stream cleanly.
func TestAbortInterruptsTheTransportButFinishDoesNot(t *testing.T) {
	newEntry := func() (*waitingConn, *abortableConn) {
		a := &abortableConn{closerFunc: closerFunc(func() error { return nil }), aborted: make(chan struct{})}
		return &waitingConn{h2Conn: a, acquired: make(chan struct{}), done: make(chan struct{})}, a
	}

	w, a := newEntry()
	w.abort()
	select {
	case <-a.aborted:
	case <-time.After(time.Second):
		t.Fatal("abort did not interrupt the transport")
	}

	w, a = newEntry()
	w.finish(true)
	select {
	case <-a.aborted:
		t.Fatal("a plain finish aborted the transport")
	default:
	}
}

// The adapter's Abort frees a Write that is stuck on the peer's flow-control
// window, which nothing else can.
func TestHTTP2AbortUnblocksAWriteStuckOnFlowControl(t *testing.T) {
	stuck := make(chan *http2ReadWriteCloser, 1)
	writeDone := make(chan error, 1)
	protocols := new(http.Protocols)
	protocols.SetHTTP1(true)
	protocols.SetUnencryptedHTTP2(true)
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		flusher, _ := w.(http.Flusher)
		flusher.Flush()
		rwc := &http2ReadWriteCloser{ReadCloser: r.Body, writer: w, flusher: flusher, abortRW: w}
		stuck <- rwc
		buf := make([]byte, 64*1024)
		for { // the client never reads, so the window fills and a Write blocks
			if _, err := rwc.Write(buf); err != nil {
				writeDone <- err
				return
			}
		}
	}))
	srv.Config.Protocols = protocols
	srv.Start()
	defer srv.Close()

	hp := new(http.Protocols)
	hp.SetUnencryptedHTTP2(true)
	tr := &http.Transport{Protocols: hp}
	defer tr.CloseIdleConnections()
	pr, pw := io.Pipe()
	defer func() { _ = pw.Close() }()
	req, _ := http.NewRequest(http.MethodPost, srv.URL, pr)
	resp, err := tr.RoundTrip(req) // headers only: the body is never read
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()

	rwc := <-stuck
	select {
	case err := <-writeDone:
		t.Fatalf("the write finished by itself: %v", err)
	case <-time.After(500 * time.Millisecond): // stuck, as intended
	}
	rwc.Abort()
	select {
	case <-writeDone:
	case <-time.After(3 * time.Second):
		t.Fatal("Abort did not free the blocked write")
	}
}

// Closing the adapter after the peer ended its request must not leave a Write
// that is stuck on the peer's flow-control window blocked for good.
func TestHTTP2CloseBoundsAWriteStuckOnFlowControl(t *testing.T) {
	old := h2CloseGrace
	h2CloseGrace = 300 * time.Millisecond
	t.Cleanup(func() { h2CloseGrace = old })
	stuck := make(chan *http2ReadWriteCloser, 1)
	writeDone := make(chan error, 1)
	protocols := new(http.Protocols)
	protocols.SetHTTP1(true)
	protocols.SetUnencryptedHTTP2(true)
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		flusher, _ := w.(http.Flusher)
		flusher.Flush()
		rwc := &http2ReadWriteCloser{ReadCloser: r.Body, writer: w, flusher: flusher, abortRW: w}
		stuck <- rwc
		buf := make([]byte, 64*1024)
		for { // the client never reads, so the window fills and a Write blocks
			if _, err := rwc.Write(buf); err != nil {
				writeDone <- err
				return
			}
		}
	}))
	srv.Config.Protocols = protocols
	srv.Start()
	defer srv.Close()

	hp := new(http.Protocols)
	hp.SetUnencryptedHTTP2(true)
	tr := &http.Transport{Protocols: hp}
	defer tr.CloseIdleConnections()
	pr, pw := io.Pipe()
	defer func() { _ = pw.Close() }()
	req, _ := http.NewRequest(http.MethodPost, srv.URL, pr)
	resp, err := tr.RoundTrip(req) // headers only: the body is never read
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()

	rwc := <-stuck
	select {
	case err := <-writeDone:
		t.Fatalf("the write finished by itself: %v", err)
	case <-time.After(500 * time.Millisecond): // stuck, as intended
	}
	_ = rwc.Close()
	select {
	case <-writeDone:
	case <-time.After(3 * time.Second):
		t.Fatal("Close did not bound the blocked write")
	}
}

// A claim that names more than one protocol is authorized as one and served as
// another. It must be refused before either happens.
func TestClaimNamingSeveralProtocolsIsRefused(t *testing.T) {
	s := NewServer(Config{WebsocketProtocol: "rust"})
	addr := startTunServer(t, s)
	sign := func(p protocol.LocalProtocol) string {
		tok, err := jwt.NewWithClaims(jwt.SigningMethodHS256, protocol.JwtTunnelConfig{
			ID: "ambiguous", Protocol: p, Remote: "127.0.0.1", Port: 0,
		}).SignedString([]byte("test-secret"))
		if err != nil {
			t.Fatal(err)
		}
		return tok
	}
	post := func(token string) int {
		req, _ := http.NewRequest(http.MethodGet, "http://"+addr+"/v1/events", nil)
		req.Header.Set("Cookie", token)
		client := &http.Client{Timeout: 3 * time.Second}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		return resp.StatusCode
	}

	for name, p := range map[string]protocol.LocalProtocol{
		"reverse tcp and udp":    {ReverseTcp: &struct{}{}, ReverseUdp: &protocol.ReverseUdpProtocol{}},
		"reverse tcp and socks5": {ReverseTcp: &struct{}{}, ReverseSocks5: &protocol.ReverseSocks5Protocol{}},
		"tcp and reverse udp":    {Tcp: &protocol.TcpProtocol{}, ReverseUdp: &protocol.ReverseUdpProtocol{}},
	} {
		if code := post(sign(p)); code != http.StatusUnauthorized {
			t.Errorf("%s: status %d, want %d", name, code, http.StatusUnauthorized)
		}
	}
}

// The target preamble is written under the entry's lock, which cancellation
// needs. A client that never takes the data must not hold it for ever.
func TestPreambleWriteGivesUpAndLeavesNoDeadline(t *testing.T) {
	server, client := net.Pipe() // unbuffered, and nothing reads the client end
	defer func() { _ = server.Close() }()
	defer func() { _ = client.Close() }()

	start := time.Now()
	err := writePreamble(server, "a.b.c", 150*time.Millisecond)
	if err == nil {
		t.Fatal("the write succeeded with nobody reading")
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("the write was bounded only after %v", elapsed)
	}

	// The deadline is cleared again: the stream is used by the pipe afterwards.
	done := make(chan error, 1)
	go func() { _, err := server.Write([]byte("x")); done <- err }()
	time.Sleep(300 * time.Millisecond) // well past the old deadline
	buf := make([]byte, 1)
	if _, err := client.Read(buf); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatalf("a deadline was left on the stream: %v", err)
	}
}

// Taking an entry from the pool must be atomic with finishing it. If a forwarder
// could count itself in after finish had already woken the handler, the handler
// would return while the forwarder still used its response writer.
func TestAcquireIsSerializedWithFinish(t *testing.T) {
	mgr := NewReverseTunnelManager(0, time.Minute)
	t.Cleanup(mgr.Close)
	tl, _, err := mgr.getOrCreateListener(reverseUDPClaims("acquire-vs-finish", nil))
	if err != nil {
		t.Fatal(err)
	}
	w := &waitingConn{acquired: make(chan struct{}), done: make(chan struct{})}
	if !mgr.enqueueWaitingConn(tl, w) {
		t.Fatal("could not queue")
	}

	// A finish is in progress: it holds the entry's lock, and ends the entry
	// before it lets go.
	w.connMu.Lock()
	type result struct {
		got *waitingConn
		ok  bool
	}
	res := make(chan result, 1)
	go func() {
		got, ok := mgr.acquireWaitingConn(tl)
		res <- result{got, ok}
	}()

	select {
	case r := <-res:
		w.connMu.Unlock()
		t.Fatalf("an entry was acquired while it was being finished (ok=%v)", r.ok)
	case <-time.After(150 * time.Millisecond):
	}

	close(w.done) // the finish completes
	w.connMu.Unlock()
	mgr.closeTunnelListener(tl, true) // nothing else will arrive: let the acquirer give up
	select {
	case r := <-res:
		if r.ok {
			t.Fatal("a finished entry was handed to a visitor")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("the acquirer never returned")
	}
}

// The target cookie has the shape of a tunnel request and every client reads it
// unchecked. Signed with the request key it could be replayed as a signed request
// by a client that never held the secret, so it is signed with a key of its own.
func TestTargetCookieCannotBeReplayedAsARequest(t *testing.T) {
	const secret = "request-secret"
	s := NewServer(Config{WebsocketProtocol: "ws", JWTSecret: secret})
	mgr := NewReverseTunnelManager(0, time.Minute).withCookieSigner(cookieSigner(secret))
	t.Cleanup(mgr.Close)

	cookie, err := mgr.targetCookie("10.0.0.1", 22)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.parseJWTClaims(cookie); err == nil {
		t.Fatal("a target cookie was accepted as a signed tunnel request")
	}

	// A request signed with the secret still passes: the check is not simply broken.
	req, err := jwt.NewWithClaims(jwt.SigningMethodHS256, protocol.JwtTunnelConfig{
		ID: "ok", Protocol: protocol.LocalProtocol{Tcp: &protocol.TcpProtocol{}}, Remote: "10.0.0.1", Port: 22,
	}).SignedString([]byte(secret))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.parseJWTClaims(req); err != nil {
		t.Fatalf("a request signed with the secret was refused: %v", err)
	}
}

// A visitor whose pumps are stuck on its own socket is released when the entry
// ends: closing the tunnel transport alone does not free a pump that is blocked
// reading from, or writing to, the visitor.
func TestVisitorSocketIsClosedWhenTheEntryEnds(t *testing.T) {
	mgr := NewReverseTunnelManager(0, time.Minute)
	t.Cleanup(mgr.Close)
	tl, _, err := mgr.getOrCreateListener(&protocol.JwtTunnelConfig{
		ID: "visitor-close", Remote: "127.0.0.1",
		Protocol: protocol.LocalProtocol{ReverseTcp: &struct{}{}},
	})
	if err != nil {
		t.Fatal(err)
	}
	// A tunnel connection whose Close does not wake its reads, as a stuck HTTP/2
	// stream behaves: the only way out is through the visitor's socket.
	block := make(chan struct{})
	t.Cleanup(func() { close(block) })
	w := &waitingConn{
		h2Conn:   blockingRW{block},
		acquired: make(chan struct{}),
		done:     make(chan struct{}),
	}
	if !mgr.enqueueWaitingConn(tl, w) {
		t.Fatal("could not queue")
	}
	visitor, err := net.Dial("tcp", tl.ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = visitor.Close() }()
	deadline := time.Now().Add(3 * time.Second)
	for !w.isAcquired() { // the visitor has been given the connection
		if time.Now().After(deadline) {
			t.Fatal("the visitor was never given the connection")
		}
		time.Sleep(10 * time.Millisecond)
	}

	w.abort() // shutdown, or the client going away
	_ = visitor.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := visitor.Read(make([]byte, 1)); err == nil || errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("the visitor's socket was left open (read err = %v)", err)
	}
}

// blockingRW is a tunnel stream that never delivers and ignores Close.
type blockingRW struct{ block chan struct{} }

func (b blockingRW) Read([]byte) (int, error)    { <-b.block; return 0, io.EOF }
func (b blockingRW) Write(p []byte) (int, error) { return len(p), nil }
func (b blockingRW) Close() error                { return nil }

// A peer's idle time runs from when it appeared. With no client parked, the wait
// for one must end when the peer expires, and what the peer sent before is not
// forwarded to a client that arrives afterwards.
func TestUDPPeerExpiresWhileWaitingForAClient(t *testing.T) {
	mgr := NewReverseTunnelManager(0, time.Minute)
	t.Cleanup(mgr.Close)
	tl, _, err := mgr.getOrCreateListener(reverseUDPClaims("udp-expire-waiting", &protocol.Duration{Nanos: 150_000_000}))
	if err != nil {
		t.Fatal(err)
	}
	peer, err := net.DialUDP("udp", nil, tl.pc.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = peer.Close() }()
	if _, err := peer.Write([]byte("stale")); err != nil {
		t.Fatal(err)
	}

	activeNow := func() int { mgr.mu.Lock(); defer mgr.mu.Unlock(); return tl.active }
	deadline := time.Now().Add(3 * time.Second) // far less than the ten second wait
	for activeNow() != 1 {
		if time.Now().After(deadline) {
			t.Fatal("the peer never started a session")
		}
		time.Sleep(10 * time.Millisecond)
	}
	for activeNow() != 0 {
		if time.Now().After(deadline) {
			t.Fatalf("the expired peer kept waiting for a client (active = %d)", activeNow())
		}
		time.Sleep(10 * time.Millisecond)
	}

	// A client arriving now must not be handed the datagram sent before the expiry.
	client := parkClient(t, mgr, tl)
	got := make(chan []byte, 1)
	go func() { _, p, _ := client.ReadMessage(); got <- p }()
	select {
	case p := <-got:
		t.Fatalf("a stale datagram %q was forwarded to a client that arrived later", p)
	case <-time.After(300 * time.Millisecond):
	}
}

func TestClosedUDPPeerDeliversNothingMore(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = pc.Close() }()
	for i := range 200 { // a closed channel and a queued datagram race in a select
		p := newUDPPeer(pc, pc.LocalAddr(), new(udpBudget))
		p.deliver([]byte("queued before the end"))
		_ = p.Close()
		if n, err := p.Read(make([]byte, 64)); err != io.EOF || n != 0 {
			t.Fatalf("iteration %d: Read after Close = %d, %v; want 0, EOF", i, n, err)
		}
	}
}
