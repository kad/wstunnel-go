// Package tuntest provides an in-memory "client host" for exercising tun
// sessions without a kernel TUN device or root.
package tuntest

import (
	"context"
	"net"
	"net/netip"
	"testing"

	"github.com/kad/wstunnel-go/pkg/tun"
	"github.com/kad/wstunnel-go/pkg/tun/internal/netstackutil"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// Inside addresses used by the host; they match the client defaults.
var (
	Addr4 = netip.MustParseAddr("198.18.0.1")
	Addr6 = netip.MustParseAddr("fd77:7473::1")
)

// Host is a userspace TCP/IP stack whose only NIC is a tun.PacketConn.
type Host struct {
	stack *stack.Stack
}

// NewHost starts a host that exchanges packets over pc until the test ends.
func NewHost(t testing.TB, pc tun.PacketConn, mtu uint32) *Host {
	t.Helper()
	s, ep, err := netstackutil.NewStack(mtu)
	if err != nil {
		t.Fatalf("tuntest: %v", err)
	}
	for _, a := range []netip.Addr{Addr4, Addr6} {
		proto := ipv4.ProtocolNumber
		if a.Is6() {
			proto = ipv6.ProtocolNumber
		}
		pa := tcpip.ProtocolAddress{Protocol: proto, AddressWithPrefix: tcpip.AddrFromSlice(a.AsSlice()).WithPrefix()}
		if terr := s.AddProtocolAddress(netstackutil.NICID, pa, stack.AddressProperties{}); terr != nil {
			t.Fatalf("tuntest: add address %s: %s", a, terr)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	go func() { _ = netstackutil.PumpOut(ctx, ep, pc.WritePacket) }()
	go func() { _ = netstackutil.PumpIn(pc.ReadPacket, ep) }()
	t.Cleanup(func() {
		cancel()
		_ = pc.Close()
		s.Close()
	})
	return &Host{stack: s}
}

// DialTCP opens a TCP connection from the host to dst through the tunnel.
func (h *Host) DialTCP(ctx context.Context, dst netip.AddrPort) (net.Conn, error) {
	fa, proto := netstackutil.FullAddress(dst)
	return gonet.DialContextTCP(ctx, h.stack, fa, proto)
}

// DialUDP opens a connected UDP socket from the host to dst through the tunnel.
func (h *Host) DialUDP(dst netip.AddrPort) (net.Conn, error) {
	fa, proto := netstackutil.FullAddress(dst)
	return gonet.DialUDP(h.stack, nil, &fa, proto)
}

// Pipe returns two connected PacketConns using the stream framing.
func Pipe() (tun.PacketConn, tun.PacketConn) {
	a, b := net.Pipe()
	return tun.NewFramedPacketConn(a), tun.NewFramedPacketConn(b)
}
