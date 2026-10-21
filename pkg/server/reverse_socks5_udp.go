package server

import (
	"encoding/binary"
	"log/slog"
	"net"
	"strconv"
	"time"

	"github.com/kad/wstunnel-go/pkg/protocol"
)

// A reverse SOCKS5 listener also relays UDP, as Rust's does: on UDP ASSOCIATE it
// answers with the address of a UDP socket bound next to the TCP listener, and
// datagrams a visitor sends there, wrapped in the SOCKS5 UDP header (RFC 1928
// section 7), are carried through the client to the destination they name. Every
// pair of visitor address and destination is one session with its own client
// connection, and what the destination answers is wrapped in the header again.
// Rust does not tie the datagrams to the TCP connection that asked, and neither
// does this.

// relayAddrFor is the address to tell a visitor to send datagrams to. A relay
// bound to every address is reached at the address the visitor used to reach the
// TCP listener, which Rust leaves for the client to work out.
func relayAddrFor(relay, via net.Addr) net.Addr {
	r, ok := relay.(*net.UDPAddr)
	if !ok || !r.IP.IsUnspecified() {
		return relay
	}
	if t, ok := via.(*net.TCPAddr); ok {
		return &net.UDPAddr{IP: t.IP, Port: r.Port}
	}
	return relay
}

// socks5ReplyAddr is socks5Reply with the address the reply carries, which for
// UDP ASSOCIATE is where to send the datagrams.
func socks5ReplyAddr(conn net.Conn, code byte, addr net.Addr) error {
	ua, ok := addr.(*net.UDPAddr)
	if !ok {
		return socks5Reply(conn, code)
	}
	reply := []byte{0x05, code, 0x00}
	if ip4 := ua.IP.To4(); ip4 != nil {
		reply = append(reply, 0x01)
		reply = append(reply, ip4...)
	} else {
		ip := ua.IP.To16()
		if ip == nil {
			ip = net.IPv6zero
		}
		reply = append(reply, 0x04)
		reply = append(reply, ip...)
	}
	reply = binary.BigEndian.AppendUint16(reply, uint16(ua.Port))
	_, err := conn.Write(reply)
	return err
}

// runSocks5UDPRelay serves the UDP side of a reverse SOCKS5 listener until the
// socket closes.
func (m *ReverseTunnelManager) runSocks5UDPRelay(tl *tunnelListener, relay net.PacketConn) {
	defer func() { _ = relay.Close() }()
	slog.Info("Reverse tunnel UDP relay started", "addr", tl.addr, "bound", relay.LocalAddr().String())

	// The same idle limit as reverse UDP: the tunnel's timeout, 30 seconds unless
	// the client said otherwise, and none for 0.
	var timeout time.Duration
	if d := tl.protocol.ReverseSocks5.Timeout; d != nil {
		timeout = time.Duration(d.Secs)*time.Second + time.Duration(d.Nanos)
	}
	creds := tl.protocol.ReverseSocks5.Credentials
	classify := func(b []byte, from net.Addr) (udpDatagram, bool) {
		// With credentials, only a sender that holds an authenticated UDP
		// association may use the relay.
		if creds != nil && !tl.assoc.Allows(protocol.AddrIP(from)) {
			slog.Debug("Reverse SOCKS5 relay: dropping datagram from a sender without an association", "from", from.String())
			return udpDatagram{}, false
		}
		host, port, n, err := protocol.ParseSocks5UDP(b)
		if err != nil {
			slog.Debug("Reverse SOCKS5 relay: skipping invalid UDP request", "from", from.String(), "err", err)
			return udpDatagram{}, false
		}
		return udpDatagram{
			key:     from.String() + "|" + net.JoinHostPort(host, strconv.Itoa(int(port))),
			payload: b[n:],
			target:  &socks5Target{host: host, port: port},
			hdr:     protocol.Socks5UDPHeader(host, port),
		}, true
	}
	m.runUDPSessions(tl, relay, timeout, classify)
}
