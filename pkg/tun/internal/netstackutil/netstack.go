// Package netstackutil holds the gVisor netstack plumbing shared by the tun
// server session and the test host.
package netstackutil

import (
	"context"
	"fmt"
	"net/netip"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
)

// NICID is the only NIC in every stack built by NewStack.
const NICID tcpip.NICID = 1

// queueLen is the outbound packet queue of the channel endpoint.
const queueLen = 512

// NewStack returns an IPv4+IPv6 TCP/UDP stack with one channel NIC whose
// default routes point at that NIC.
//
// Martian loopback filtering is turned off on purpose. Whether a tun flow may
// reach a loopback address is decided by the caller's authorization hook, in
// one place, so that an explicit restriction rule can permit it.
func NewStack(mtu uint32) (*stack.Stack, *channel.Endpoint, error) {
	s := stack.New(stack.Options{
		NetworkProtocols: []stack.NetworkProtocolFactory{
			ipv4.NewProtocolWithOptions(ipv4.Options{AllowExternalLoopbackTraffic: true}),
			ipv6.NewProtocolWithOptions(ipv6.Options{AllowExternalLoopbackTraffic: true}),
		},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol},
	})
	ep := channel.New(queueLen, mtu, "")
	if terr := s.CreateNIC(NICID, ep); terr != nil {
		s.Close()
		return nil, nil, fmt.Errorf("netstack: create NIC: %s", terr)
	}
	s.SetRouteTable([]tcpip.Route{
		{Destination: header.IPv4EmptySubnet, NIC: NICID},
		{Destination: header.IPv6EmptySubnet, NIC: NICID},
	})
	return s, ep, nil
}

// PumpIn injects every packet returned by read into ep until read fails.
// Packets that are neither IPv4 nor IPv6 are dropped.
func PumpIn(read func() ([]byte, error), ep *channel.Endpoint) error {
	for {
		b, err := read()
		if err != nil {
			return err
		}
		if len(b) == 0 {
			continue
		}
		var proto tcpip.NetworkProtocolNumber
		switch b[0] >> 4 {
		case 4:
			proto = ipv4.ProtocolNumber
		case 6:
			proto = ipv6.ProtocolNumber
		default:
			continue
		}
		// MakeWithData copies b, so read may reuse its buffer.
		pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(b)})
		ep.InjectInbound(proto, pkt)
		pkt.DecRef()
	}
}

// PumpOut passes every packet the stack emits on ep to write until ctx ends
// or write fails. write must not retain its argument.
func PumpOut(ctx context.Context, ep *channel.Endpoint, write func([]byte) error) error {
	for {
		pkt := ep.ReadContext(ctx)
		if pkt == nil {
			return ctx.Err()
		}
		v := pkt.ToView()
		err := write(v.AsSlice())
		v.Release()
		pkt.DecRef()
		if err != nil {
			return err
		}
	}
}

// AddrPort converts a netstack address and port to a netip.AddrPort.
func AddrPort(a tcpip.Address, port uint16) netip.AddrPort {
	ip, _ := netip.AddrFromSlice(a.AsSlice())
	return netip.AddrPortFrom(ip, port)
}

// FullAddress converts a netip.AddrPort to a netstack address on NICID, plus
// the matching network protocol.
func FullAddress(ap netip.AddrPort) (tcpip.FullAddress, tcpip.NetworkProtocolNumber) {
	proto := ipv4.ProtocolNumber
	if ap.Addr().Is6() && !ap.Addr().Is4In6() {
		proto = ipv6.ProtocolNumber
	}
	a := ap.Addr().Unmap()
	return tcpip.FullAddress{NIC: NICID, Addr: tcpip.AddrFromSlice(a.AsSlice()), Port: ap.Port()}, proto
}
