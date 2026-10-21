package server

import (
	"bytes"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/kad/wstunnel-go/pkg/protocol"
	"github.com/kad/wstunnel-go/pkg/wst"
)

func socks5Claims(id string) *protocol.JwtTunnelConfig {
	return &protocol.JwtTunnelConfig{
		ID: id, Remote: "127.0.0.1", Port: 0,
		Protocol: protocol.LocalProtocol{ReverseSocks5: &protocol.ReverseSocks5Protocol{Timeout: &protocol.Duration{Secs: 5}}},
	}
}

// A visitor that asks for UDP ASSOCIATE is told where the relay is, and the
// datagrams it sends there reach a client, which is told the destination as a UDP
// target. What the client answers comes back wrapped in the SOCKS5 UDP header.
func TestReverseSocks5UDPAssociate(t *testing.T) {
	mgr := NewReverseTunnelManager(0, time.Minute)
	t.Cleanup(mgr.Close)
	mgr.withCookieSigner(cookieSigner("test-secret"))
	tl, _, err := mgr.getOrCreateListener(socks5Claims("socks-udp"))
	if err != nil {
		t.Fatal(err)
	}
	if tl.relay == nil {
		t.Fatal("no UDP relay was bound")
	}

	// A held client request, whose upgrade completes once a destination is known.
	server, clientEnd := net.Pipe()
	t.Cleanup(func() { _ = server.Close(); _ = clientEnd.Close() })
	cookie := make(chan string, 1)
	wait := &waitingConn{acquired: make(chan struct{}), done: make(chan struct{})}
	wait.lazy = func(extra http.Header) error {
		cookie <- extra.Get("Cookie")
		wait.wsConn = wst.NewConn(server, false)
		return nil
	}
	if !mgr.enqueueWaitingConn(tl, wait) {
		t.Fatal("could not queue the held request")
	}
	client := wst.NewConn(clientEnd, false)

	// The visitor associates over TCP.
	ctrl, err := net.DialTimeout("tcp", tl.ln.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ctrl.Close() }()
	_ = ctrl.SetDeadline(time.Now().Add(5 * time.Second))
	_, _ = ctrl.Write([]byte{5, 1, 0})
	greeting := make([]byte, 2)
	if _, err := io.ReadFull(ctrl, greeting); err != nil {
		t.Fatal(err)
	}
	_, _ = ctrl.Write([]byte{5, 3, 0, 1, 0, 0, 0, 0, 0, 0})
	reply := make([]byte, 10)
	if _, err := io.ReadFull(ctrl, reply); err != nil || reply[1] != socks5Succeeded || reply[3] != 0x01 {
		t.Fatalf("associate reply %v, %v", reply, err)
	}
	relay := &net.UDPAddr{IP: net.IP(reply[4:8]), Port: int(reply[8])<<8 | int(reply[9])}

	// It sends a datagram for 10.9.8.7:5353 to the relay.
	visitor, err := net.DialUDP("udp", nil, relay)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = visitor.Close() }()
	header := protocol.Socks5UDPHeader("10.9.8.7", 5353)
	if _, err := visitor.Write(append(append([]byte(nil), header...), "query"...)); err != nil {
		t.Fatal(err)
	}

	// The client was told to reach it over UDP, and receives the payload alone.
	select {
	case c := <-cookie:
		claims := &protocol.JwtTunnelConfig{}
		if _, _, err := jwt.NewParser().ParseUnverified(c, claims); err != nil {
			t.Fatal(err)
		}
		if claims.Protocol.Udp == nil || claims.Protocol.Tcp != nil || claims.Remote != "10.9.8.7" || claims.Port != 5353 {
			t.Fatalf("target %+v, want UDP 10.9.8.7:5353", claims)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("the held request was not answered")
	}
	_ = client.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, p, err := client.ReadMessage(); err != nil || string(p) != "query" {
		t.Fatalf("client got %q, %v; want the bare payload", p, err)
	}

	// The answer comes back to the visitor wrapped in the header of the destination.
	if err := client.WriteMessage(wst.BinaryMessage, []byte("answer")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 128)
	_ = visitor.SetReadDeadline(time.Now().Add(3 * time.Second))
	n, err := visitor.Read(buf)
	if err != nil || !bytes.Equal(buf[:n], append(append([]byte(nil), header...), "answer"...)) {
		t.Fatalf("visitor got %v, %v; want the header and \"answer\"", buf[:n], err)
	}
}

func TestReverseSocks5AssociateRefusedWithoutRelay(t *testing.T) {
	// Take the UDP port first, so the listener gets its TCP port but no relay.
	taken, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = taken.Close() }()
	claims := socks5Claims("socks-udp-norelay")
	claims.Port = uint16(taken.LocalAddr().(*net.UDPAddr).Port)

	mgr := NewReverseTunnelManager(0, time.Minute)
	t.Cleanup(mgr.Close)
	tl, _, err := mgr.getOrCreateListener(claims)
	if err != nil {
		t.Fatal(err)
	}
	if tl.relay != nil {
		t.Fatal("the relay was bound on a taken port")
	}

	conn, err := net.DialTimeout("tcp", tl.ln.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	_, _ = conn.Write([]byte{5, 1, 0})
	greeting := make([]byte, 2)
	_, _ = io.ReadFull(conn, greeting)
	_, _ = conn.Write([]byte{5, 3, 0, 1, 0, 0, 0, 0, 0, 0})
	reply := make([]byte, 10)
	if _, err := io.ReadFull(conn, reply); err != nil || reply[1] != socks5CommandNotSupported {
		t.Fatalf("reply %v, %v; want command not supported", reply, err)
	}
}

func TestRelayAddrForUnspecifiedBind(t *testing.T) {
	relay := &net.UDPAddr{IP: net.IPv4zero, Port: 1080}
	via := &net.TCPAddr{IP: net.ParseIP("192.0.2.5"), Port: 1080}
	got := relayAddrFor(relay, via).(*net.UDPAddr)
	if !got.IP.Equal(via.IP) || got.Port != 1080 {
		t.Fatalf("got %v, want the address the visitor reached the listener at", got)
	}
	specific := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1080}
	if relayAddrFor(specific, via) != net.Addr(specific) {
		t.Fatal("a relay bound to a specific address must be reported as is")
	}
}

// With credentials, only a sender that holds an authenticated association may use
// the relay: a datagram from anyone else does not take a held client request.
func TestReverseSocks5UDPRelayNeedsAnAssociationWithCredentials(t *testing.T) {
	mgr := NewReverseTunnelManager(0, time.Minute)
	t.Cleanup(mgr.Close)
	mgr.withCookieSigner(cookieSigner("test-secret"))
	claims := socks5Claims("socks-udp-auth")
	claims.Protocol.ReverseSocks5.Credentials = &protocol.Credentials{Username: "admin", Password: "secret"}
	tl, _, err := mgr.getOrCreateListener(claims)
	if err != nil {
		t.Fatal(err)
	}

	server, clientEnd := net.Pipe()
	t.Cleanup(func() { _ = server.Close(); _ = clientEnd.Close() })
	cookie := make(chan string, 1)
	wait := &waitingConn{acquired: make(chan struct{}), done: make(chan struct{})}
	wait.lazy = func(extra http.Header) error {
		cookie <- extra.Get("Cookie")
		wait.wsConn = wst.NewConn(server, false)
		return nil
	}
	if !mgr.enqueueWaitingConn(tl, wait) {
		t.Fatal("could not queue the held request")
	}

	visitor, err := net.DialUDP("udp", nil, tl.relay.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = visitor.Close() }()
	datagram := append(protocol.Socks5UDPHeader("10.9.8.7", 5353), "query"...)

	// No association: dropped, and the held request is untouched.
	if _, err := visitor.Write(datagram); err != nil {
		t.Fatal(err)
	}
	select {
	case <-cookie:
		t.Fatal("a sender without an association took a held client request")
	case <-time.After(400 * time.Millisecond):
	}

	// After an authenticated UDP ASSOCIATE from the same address it is served.
	ctrl, err := net.DialTimeout("tcp", tl.ln.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ctrl.Close() }()
	_ = ctrl.SetDeadline(time.Now().Add(5 * time.Second))
	_, _ = ctrl.Write([]byte{5, 1, 2})
	if g := make([]byte, 2); func() bool { _, err := io.ReadFull(ctrl, g); return err != nil || g[1] != 2 }() {
		t.Fatal("the listener did not ask for a password")
	}
	_, _ = ctrl.Write(append(append([]byte{1, 5}, "admin"...), append([]byte{6}, "secret"...)...))
	status := make([]byte, 2)
	if _, err := io.ReadFull(ctrl, status); err != nil || status[1] != 0 {
		t.Fatalf("authentication: %v %v", status, err)
	}
	_, _ = ctrl.Write([]byte{5, 3, 0, 1, 0, 0, 0, 0, 0, 0})
	reply := make([]byte, 10)
	if _, err := io.ReadFull(ctrl, reply); err != nil || reply[1] != socks5Succeeded {
		t.Fatalf("associate reply %v, %v", reply, err)
	}
	if _, err := visitor.Write(datagram); err != nil {
		t.Fatal(err)
	}
	select {
	case <-cookie:
	case <-time.After(3 * time.Second):
		t.Fatal("an authenticated sender was not served")
	}
}

// checkingConn reports, when the UDP ASSOCIATE success reply is written, whether
// the visitor's address already counted as associated.
type checkingConn struct {
	net.Conn
	allowed func() bool
	atReply chan bool
}

func (c *checkingConn) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 40000}
}
func (c *checkingConn) LocalAddr() net.Addr {
	return &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1080}
}
func (c *checkingConn) Write(p []byte) (int, error) {
	if len(p) == 10 && p[0] == 5 && p[1] == socks5Succeeded {
		select {
		case c.atReply <- c.allowed():
		default:
		}
	}
	return c.Conn.Write(p)
}

// The association is registered before the success reply goes out, since the
// visitor may send its first datagram as soon as it has read it.
func TestReverseSocks5AssociationIsRegisteredBeforeTheReply(t *testing.T) {
	mgr := NewReverseTunnelManager(0, time.Minute)
	t.Cleanup(mgr.Close)
	claims := socks5Claims("socks-udp-order")
	claims.Protocol.ReverseSocks5.Credentials = &protocol.Credentials{Username: "admin", Password: "secret"}
	tl, _, err := mgr.getOrCreateListener(claims)
	if err != nil {
		t.Fatal(err)
	}

	serverEnd, client := net.Pipe()
	defer func() { _ = client.Close() }()
	cc := &checkingConn{Conn: serverEnd, atReply: make(chan bool, 1)}
	cc.allowed = func() bool { return tl.assoc.Allows(net.ParseIP("127.0.0.1")) }
	go func() {
		mgr.beginIncoming(tl)
		mgr.handleIncoming(tl, cc)
	}()

	_ = client.SetDeadline(time.Now().Add(5 * time.Second))
	_, _ = client.Write([]byte{5, 1, 2})
	_, _ = io.ReadFull(client, make([]byte, 2))
	_, _ = client.Write(append(append([]byte{1, 5}, "admin"...), append([]byte{6}, "secret"...)...))
	_, _ = io.ReadFull(client, make([]byte, 2))
	_, _ = client.Write([]byte{5, 3, 0, 1, 0, 0, 0, 0, 0, 0})
	go func() { _, _ = io.ReadFull(client, make([]byte, 10)) }()
	select {
	case allowed := <-cc.atReply:
		if !allowed {
			t.Fatal("the success reply went out before the association was registered")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("no success reply")
	}
}
