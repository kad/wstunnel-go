package client

import (
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
)

type netOpKind int

const (
	opSetMTU netOpKind = iota
	opAddAddr
	opLinkUp
	opAddRoute
)

// netOp is one step of configuring the TUN device.
type netOp struct {
	Kind   netOpKind
	MTU    int
	Prefix netip.Prefix
	// Optional steps are logged and skipped on failure instead of aborting
	// startup. Only the built-in default IPv6 address is optional, because
	// hosts with IPv6 disabled cannot take it.
	Optional bool
}

// netConfigurer applies netOps to a named interface. The Linux implementation
// speaks netlink; tests use a recording fake.
type netConfigurer interface {
	SetMTU(ifname string, mtu int) error
	AddAddr(ifname string, p netip.Prefix) error
	LinkUp(ifname string) error
	AddRoute(ifname string, dst netip.Prefix) error
}

// planTunNetConfig returns the ordered steps that configure a device created
// for spec, and refuses configurations that would loop the tunnel's own
// traffic into the device.
//
// Loop guard: if a route contains the tunnel server's address, the packets that
// carry the tunnel would themselves be routed into the TUN and never leave the
// host. Full-tunnel routing (a later milestone) handles that case properly.
func planTunNetConfig(spec *TunSpec, serverAddrs []netip.Addr) ([]netOp, error) {
	if !spec.Configure {
		return nil, nil
	}
	if err := checkTunLoops(spec, serverAddrs); err != nil {
		return nil, err
	}

	ops := []netOp{{Kind: opSetMTU, MTU: int(spec.MTU)}}
	for _, addr := range spec.Addrs {
		ops = append(ops, netOp{
			Kind:     opAddAddr,
			Prefix:   addr,
			Optional: spec.DefaultAddrs && addr.Addr().Is6(),
		})
	}
	ops = append(ops, netOp{Kind: opLinkUp})
	for _, route := range spec.Routes {
		ops = append(ops, netOp{Kind: opAddRoute, Prefix: route})
	}
	return ops, nil
}

// checkTunLoops refuses a configuration whose routes or connected addresses
// would send the tunnel's own traffic to the server into the device. It is a
// pure function of the spec and the server addresses, so the client can run it
// again whenever the server name resolves to something new. Without a known
// server address it fails closed.
func checkTunLoops(spec *TunSpec, serverAddrs []netip.Addr) error {
	if !spec.Configure {
		return nil
	}
	if len(spec.Routes) > 0 && len(serverAddrs) == 0 {
		return errors.New("cannot check tun:// routes against the tunnel server because its address is unknown")
	}
	for _, route := range spec.Routes {
		if err := checkNotWholeHost(normalizePrefix(route)); err != nil {
			return err
		}
	}
	servers := make([]netip.Addr, 0, len(serverAddrs))
	for _, server := range serverAddrs {
		servers = append(servers, server.WithZone("").Unmap())
	}
	for _, route := range spec.Routes {
		if err := checkLoop(normalizePrefix(route), "route", route, servers); err != nil {
			return err
		}
	}
	for _, addr := range spec.Addrs {
		// An address shorter than a host prefix makes the kernel install a
		// route for its whole network into the device.
		if addr.Bits() < addr.Addr().BitLen() {
			if err := checkLoop(normalizePrefix(addr).Masked(), "addr", addr, servers); err != nil {
				return err
			}
		}
	}
	return nil
}

// normalizePrefix turns a 4in6 prefix such as ::ffff:203.0.113.0/120 into the
// IPv4 prefix it names.
func normalizePrefix(p netip.Prefix) netip.Prefix {
	if p.Addr().Is4In6() && p.Bits() >= 96 {
		return netip.PrefixFrom(p.Addr().Unmap(), p.Bits()-96)
	}
	return p
}

// checkNotWholeHost refuses a default route and the two /1 halves that together
// make one. They would capture all of the host's traffic of that family, DNS and
// replies to inbound connections included; full-tunnel routing needs more than
// a route and is not supported yet.
func checkNotWholeHost(p netip.Prefix) error {
	p = p.Masked()
	if p.Bits() > 1 {
		return nil
	}
	if p.Bits() == 1 {
		switch p.Addr() {
		case netip.AddrFrom4([4]byte{}), netip.AddrFrom4([4]byte{128}),
			netip.IPv6Unspecified(), netip.MustParseAddr("8000::"):
		default:
			return nil
		}
	}
	family := "IPv4"
	if p.Addr().Is6() {
		family = "IPv6"
	}
	return fmt.Errorf("tun:// route %s would capture all %s traffic; routing the whole host through the tunnel is not supported yet", p, family)
}

// checkLoop refuses a network routed into the device that holds a tunnel server.
func checkLoop(network netip.Prefix, kind string, spec netip.Prefix, servers []netip.Addr) error {
	for _, server := range servers {
		if !network.Contains(server) {
			continue
		}
		if kind == "addr" {
			return fmt.Errorf("tun:// addr %s creates a connected route for %s, which contains the tunnel server %s: the tunnel's own traffic would loop into the tunnel; use a host prefix (/32 or /128)", spec, network, server)
		}
		return fmt.Errorf("tun:// route %s contains the tunnel server %s: the tunnel's own traffic would loop into the tunnel", spec, server)
	}
	return nil
}

// applyNetOps runs ops against ifname in order.
func applyNetOps(ifname string, ops []netOp, nl netConfigurer) error {
	for _, op := range ops {
		var err error
		switch op.Kind {
		case opSetMTU:
			err = nl.SetMTU(ifname, op.MTU)
		case opAddAddr:
			err = nl.AddAddr(ifname, op.Prefix)
		case opLinkUp:
			err = nl.LinkUp(ifname)
		case opAddRoute:
			err = nl.AddRoute(ifname, op.Prefix)
		}
		if err == nil {
			continue
		}
		if op.Optional {
			slog.Warn("Skipping optional tun configuration", "interface", ifname, "address", op.Prefix, "err", err)
			continue
		}
		return fmt.Errorf("configure %s: %s: %w", ifname, op.describe(), err)
	}
	return nil
}

func (op netOp) describe() string {
	switch op.Kind {
	case opSetMTU:
		return fmt.Sprintf("set mtu %d", op.MTU)
	case opAddAddr:
		return fmt.Sprintf("add address %s", op.Prefix)
	case opLinkUp:
		return "bring link up"
	case opAddRoute:
		return fmt.Sprintf("add route %s", op.Prefix)
	}
	return "unknown step"
}
