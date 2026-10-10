package client

import (
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
	for _, route := range spec.Routes {
		for _, server := range serverAddrs {
			if route.Contains(server.Unmap()) {
				return nil, fmt.Errorf("tun:// route %s contains the tunnel server %s: the tunnel's own traffic would loop into the tunnel", route, server.Unmap())
			}
		}
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
