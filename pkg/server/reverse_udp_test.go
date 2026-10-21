package server

import (
	"bytes"
	"log/slog"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kad/wstunnel-go/pkg/protocol"
	"github.com/kad/wstunnel-go/pkg/wst"
)

func reverseUDPClaims(id string, timeout *protocol.Duration) *protocol.JwtTunnelConfig {
	return &protocol.JwtTunnelConfig{
		ID:       id,
		Remote:   "127.0.0.1",
		Port:     0,
		Protocol: protocol.LocalProtocol{ReverseUdp: &protocol.ReverseUdpProtocol{Timeout: timeout}},
	}
}

// parkClient queues a client connection (the websocket side the server holds)
// and returns the end the client would read and write.
func parkClient(t *testing.T, mgr *ReverseTunnelManager, tl *tunnelListener) *wst.Conn {
	t.Helper()
	server, client := net.Pipe()
	t.Cleanup(func() { _ = server.Close(); _ = client.Close() })
	wait := &waitingConn{
		wsConn:   wst.NewConn(server, false),
		acquired: make(chan struct{}),
		done:     make(chan struct{}),
	}
	if !mgr.enqueueWaitingConn(tl, wait) {
		t.Fatal("could not queue the client connection")
	}
	return wst.NewConn(client, false)
}

// Each UDP peer is given its own client connection, one message per datagram,
// and replies go back to that peer alone.
func TestReverseUDPListenerGivesEachPeerItsOwnClient(t *testing.T) {
	mgr := NewReverseTunnelManager(0, time.Minute)
	t.Cleanup(mgr.Close)
	tl, _, err := mgr.getOrCreateListener(reverseUDPClaims("udp-peers", nil))
	if err != nil {
		t.Fatal(err)
	}
	listenAddr := tl.pc.LocalAddr()

	clients := []*wst.Conn{parkClient(t, mgr, tl), parkClient(t, mgr, tl)}

	peer := func() *net.UDPConn {
		c, err := net.DialUDP("udp", nil, listenAddr.(*net.UDPAddr))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = c.Close() })
		return c
	}
	a, b := peer(), peer()
	if _, err := a.Write([]byte("from a")); err != nil {
		t.Fatal(err)
	}
	// The first peer takes the first parked client; read its datagram there.
	_ = clientsRead(t, clients[0], "from a")
	if _, err := b.Write([]byte("from b")); err != nil {
		t.Fatal(err)
	}
	_ = clientsRead(t, clients[1], "from b")

	// Replies reach the right peer only.
	if err := clients[1].WriteMessage(wst.BinaryMessage, []byte("to b")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 64)
	_ = b.SetReadDeadline(time.Now().Add(3 * time.Second))
	n, err := b.Read(buf)
	if err != nil || !bytes.Equal(buf[:n], []byte("to b")) {
		t.Fatalf("peer b got %q, %v, want \"to b\"", buf[:n], err)
	}
	_ = a.SetReadDeadline(time.Now().Add(150 * time.Millisecond))
	if n, err := a.Read(buf); err == nil {
		t.Fatalf("peer a got %q meant for b", buf[:n])
	}
}

func clientsRead(t *testing.T, c *wst.Conn, want string) []byte {
	t.Helper()
	got := make(chan []byte, 1)
	go func() {
		_, p, err := c.ReadMessage()
		if err != nil {
			p = nil
		}
		got <- p
	}()
	select {
	case p := <-got:
		if string(p) != want {
			t.Fatalf("client read %q, want %q", p, want)
		}
		return p
	case <-time.After(3 * time.Second):
		t.Fatalf("client never received %q", want)
		return nil
	}
}

// A peer that stays silent for the tunnel's timeout loses its session, and the
// client connection it held is released.
func TestReverseUDPPeerExpiresAfterTimeout(t *testing.T) {
	mgr := NewReverseTunnelManager(0, time.Minute)
	t.Cleanup(mgr.Close)
	tl, _, err := mgr.getOrCreateListener(reverseUDPClaims("udp-timeout", &protocol.Duration{Nanos: 200_000_000}))
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

	// Silence: the server ends the session and closes the client's connection.
	closed := make(chan error, 1)
	go func() {
		_, _, err := client.ReadMessage()
		closed <- err
	}()
	select {
	case err := <-closed:
		if err == nil {
			t.Fatal("client read a message instead of the end of the session")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("idle UDP session was not ended")
	}
}

func TestUDPPeerDropsDatagramsWhenQueueIsFull(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = pc.Close() }()
	p := newUDPPeer(pc, pc.LocalAddr(), new(udpBudget))
	for range udpPeerQueue + 10 {
		p.deliver([]byte("x"))
	}
	if got := len(p.in); got != udpPeerQueue {
		t.Fatalf("queued %d datagrams, want the queue capped at %d", got, udpPeerQueue)
	}
}

// A peer that keeps sending while the tunnel is not draining still counts as
// active: its dropped datagrams must not let the idle timer expire it.
func TestDroppedDatagramsStillCountAsActivity(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = pc.Close() }()
	p := newUDPPeer(pc, pc.LocalAddr(), new(udpBudget))
	for range udpPeerQueue { // the queue is full and nothing drains it
		p.deliver([]byte("x"))
	}
	time.Sleep(150 * time.Millisecond)
	p.deliver([]byte("dropped, but the peer is alive"))
	if idle := p.idle(time.Now()); idle > 50*time.Millisecond {
		t.Fatalf("idle = %v after a datagram arrived, want it to have been refreshed", idle)
	}
}

// Beyond the peer limit a new source is ignored, and the peers already admitted
// keep their sessions.
func TestReverseUDPListenerCapsPeers(t *testing.T) {
	old := maxUDPPeers
	maxUDPPeers = 1
	t.Cleanup(func() { maxUDPPeers = old })

	mgr := NewReverseTunnelManager(0, time.Minute)
	t.Cleanup(mgr.Close)
	tl, _, err := mgr.getOrCreateListener(reverseUDPClaims("udp-cap", nil))
	if err != nil {
		t.Fatal(err)
	}
	clients := []*wst.Conn{parkClient(t, mgr, tl), parkClient(t, mgr, tl)}

	peer := func() *net.UDPConn {
		c, err := net.DialUDP("udp", nil, tl.pc.LocalAddr().(*net.UDPAddr))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = c.Close() })
		return c
	}
	a, b := peer(), peer()
	if _, err := a.Write([]byte("one")); err != nil {
		t.Fatal(err)
	}
	_ = clientsRead(t, clients[0], "one")

	if _, err := b.Write([]byte("two")); err != nil {
		t.Fatal(err)
	}
	got := make(chan struct{}, 1)
	go func() {
		if _, _, err := clients[1].ReadMessage(); err == nil {
			got <- struct{}{}
		}
	}()
	select {
	case <-got:
		t.Fatal("a peer over the limit was given a session")
	case <-time.After(300 * time.Millisecond):
	}

	// The admitted peer is still served.
	if _, err := a.Write([]byte("again")); err != nil {
		t.Fatal(err)
	}
	_ = clientsRead(t, clients[0], "again")
}

// The bytes a listener queues are capped across its peers, and come back when
// they are read or the peer ends.
func TestUDPQueuedBytesAreBudgeted(t *testing.T) {
	old := maxUDPQueuedBytes
	maxUDPQueuedBytes = 100
	t.Cleanup(func() { maxUDPQueuedBytes = old })

	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = pc.Close() }()
	budget := new(udpBudget)
	a := newUDPPeer(pc, pc.LocalAddr(), budget)
	b := newUDPPeer(pc, pc.LocalAddr(), budget)

	a.deliver(make([]byte, 60))
	b.deliver(make([]byte, 60)) // over the listener's budget
	if len(b.in) != 0 || budget.used.Load() != 60 {
		t.Fatalf("queued %d datagrams for b, %d bytes used; want the second peer's dropped", len(b.in), budget.used.Load())
	}
	buf := make([]byte, 100)
	if _, err := a.Read(buf); err != nil {
		t.Fatal(err)
	}
	if got := budget.used.Load(); got != 0 {
		t.Fatalf("%d bytes still reserved after the read", got)
	}
	b.deliver(make([]byte, 60))
	_ = b.Close()
	a.deliver(make([]byte, 10))
	b.deliver(make([]byte, 10)) // closed: not queued
	if got := budget.used.Load(); got != 10 {
		t.Fatalf("%d bytes reserved, want 10 (a's datagram only)", got)
	}
}

// A parked HTTP/2 or WebTransport connection whose client went away leaves the
// pool at once instead of waiting for a visitor to find it dead.
func TestParkedConnectionLeavesPoolWhenClientGoesAway(t *testing.T) {
	mgr := NewReverseTunnelManager(0, time.Minute)
	t.Cleanup(mgr.Close)
	claims := &protocol.JwtTunnelConfig{
		ID: "parked-gone", Remote: "127.0.0.1",
		Protocol: protocol.LocalProtocol{ReverseTcp: &struct{}{}},
	}
	tl, _, err := mgr.getOrCreateListener(claims)
	if err != nil {
		t.Fatal(err)
	}
	gone := make(chan struct{})
	conn := &nopReadWriteCloser{closed: make(chan struct{})}
	returned := make(chan struct{})
	go func() {
		mgr.HandleClientH2(conn, claims, gone)
		close(returned)
	}()
	time.Sleep(100 * time.Millisecond) // parked
	close(gone)
	select {
	case <-returned:
	case <-time.After(3 * time.Second):
		t.Fatal("the handler kept a parked connection whose client was gone")
	}
	select {
	case <-conn.closed:
	default:
		t.Error("the connection was not closed")
	}
	tl.queueMu.Lock()
	defer tl.queueMu.Unlock()
	for _, w := range tl.waiting {
		if w != nil && !isClosed(w.done) {
			t.Error("a dead entry is still in the pool")
		}
	}
}

// A client message bigger than any datagram ends the session. (The read limit
// that keeps the server from buffering such a message first is not observable
// from here; the datagram write would reject it either way.)
func TestReverseUDPOversizedClientMessageEndsSession(t *testing.T) {
	mgr := NewReverseTunnelManager(0, time.Minute)
	t.Cleanup(mgr.Close)
	tl, _, err := mgr.getOrCreateListener(reverseUDPClaims("udp-limit", nil))
	if err != nil {
		t.Fatal(err)
	}
	client := parkClient(t, mgr, tl)
	peer, err := net.DialUDP("udp", nil, tl.pc.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = peer.Close() }()
	if _, err := peer.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	_ = clientsRead(t, client, "hello")

	go func() { _ = client.WriteMessage(wst.BinaryMessage, make([]byte, 200_000)) }()
	closed := make(chan error, 1)
	go func() {
		_, _, err := client.ReadMessage()
		closed <- err
	}()
	select {
	case err := <-closed:
		if err == nil {
			t.Fatal("the oversized message was accepted")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("the session survived an oversized message")
	}
}

// A reverse listener asked to bind port 0 logs the port it got.
func TestReverseListenerLogsBoundAddress(t *testing.T) {
	var buf syncBuffer
	old := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, nil)))
	t.Cleanup(func() { slog.SetDefault(old) })

	mgr := NewReverseTunnelManager(0, time.Minute)
	t.Cleanup(mgr.Close)
	tl, _, err := mgr.getOrCreateListener(&protocol.JwtTunnelConfig{
		ID: "bound", Remote: "127.0.0.1", Port: 0,
		Protocol: protocol.LocalProtocol{ReverseTcp: &struct{}{}},
	})
	if err != nil {
		t.Fatal(err)
	}
	want := "bound=" + tl.ln.Addr().String()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) && !strings.Contains(buf.String(), want) {
		time.Sleep(10 * time.Millisecond)
	}
	if !strings.Contains(buf.String(), want) {
		t.Fatalf("log %q lacks %q", buf.String(), want)
	}
	if strings.HasSuffix(tl.ln.Addr().String(), ":0") {
		t.Fatal("the listener did not get a real port")
	}
}

type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}
