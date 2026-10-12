package client

import (
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"slices"
	"strings"
	"syscall"
)

const (
	// defaultTunMark is the fwmark used to exempt the client's own sockets from
	// the tunnel when --socket-so-mark is not given. It is also the routing
	// table id.
	defaultTunMark uint32 = 0x7774

	// The two rules of fwmark routing. They sit below the default rules of the
	// main table (32766) but at priorities of their own, because wg-quick uses
	// 32764 and 32765 for the same shape of rule and the startup purge must
	// never touch another program's rules. Only these two priorities are ever
	// removed by the purge.
	rulePrioSuppress = 32760 // lookup main suppress_prefixlength 0
	rulePrioMark     = 32761 // not fwmark M lookup M
)

// rpFilterStrict is the value of the rp_filter sysctl for strict reverse-path
// filtering. 0 is off and 2 is loose.
const rpFilterStrict = 1

// tunMark returns the fwmark (and routing table id) a full tunnel uses.
func tunMark(socketSoMark uint32) uint32 {
	if socketSoMark != 0 {
		return socketSoMark
	}
	return defaultTunMark
}

// checkTunMark refuses marks that cannot be used as a routing table id: 0 is
// unspecified and 253..255 are the kernel's default, main and local tables.
func checkTunMark(mark uint32) error {
	switch mark {
	case 0, 253, 254, 255:
		return fmt.Errorf("--socket-so-mark %d cannot be used for a full tunnel: it is also the routing table id and %d is reserved; pick another mark", mark, mark)
	}
	return nil
}

// routeInfo is the route the host uses to reach an address.
type routeInfo struct {
	// Gateway is the next hop; invalid when the destination is on-link.
	Gateway netip.Addr
	// Link is the egress interface name.
	Link string
	// Src is the preferred source address of the route, if any.
	Src netip.Addr
	// ExactHost is set when the route found is itself a host route (/32 or
	// /128) for the address. It already keeps that address off the tunnel, and
	// it is not ours, so it is neither re-added nor removed.
	ExactHost bool
}

// routeGetter answers "how does this host reach ip". Tests use a table; the
// Linux implementation asks the kernel's routing table.
type routeGetter interface {
	RouteGet(ip netip.Addr) (routeInfo, error)
}

// routeGetFunc adapts a function to routeGetter.
type routeGetFunc func(ip netip.Addr) (routeInfo, error)

func (f routeGetFunc) RouteGet(ip netip.Addr) (routeInfo, error) { return f(ip) }

// routingConfig is everything the full-tunnel planner needs besides the
// servers.
type routingConfig struct {
	// Mode is "fwmark" or "pin" (never "auto": chooseRouting resolves it).
	Mode string
	// Mark is the fwmark of the client's own sockets and the routing table id
	// (fwmark mode).
	Mark uint32
	// Tun is the device name.
	Tun string
}

// ruleSpec is one policy routing rule.
type ruleSpec struct {
	Family   int // 4 or 6
	Priority int
	Table    int
	// Mark and NotMark select "not fwmark Mark" when NotMark is set.
	Mark    uint32
	NotMark bool
	// Suppress is the suppress_prefixlength value; negative for none.
	Suppress int
	// Selectors describes anything else the rule matches on or does (source,
	// destination, interface, ports, a partial mark mask, ...). It is only
	// filled in when listing rules; a rule of ours never has any, so a rule
	// with selectors is somebody else's.
	Selectors string
}

func (r ruleSpec) String() string {
	var b strings.Builder
	fmt.Fprintf(&b, "ipv%d pref %d", r.Family, r.Priority)
	if r.NotMark {
		fmt.Fprintf(&b, " not fwmark %#x", r.Mark)
	}
	fmt.Fprintf(&b, " table %d", r.Table)
	if r.Suppress >= 0 {
		fmt.Fprintf(&b, " suppress_prefixlength %d", r.Suppress)
	}
	if r.Selectors != "" {
		fmt.Fprintf(&b, " [%s]", r.Selectors)
	}
	return b.String()
}

// fullTunnelRules are the two policy rules of fwmark routing for one family,
// in installation order: the suppress rule first, so main-table routes more
// specific than the default keep winning from the moment the catch-all rule
// appears.
func fullTunnelRules(family int, mark uint32) []ruleSpec {
	return []ruleSpec{
		{Family: family, Priority: rulePrioSuppress, Table: 254, Suppress: 0},
		{Family: family, Priority: rulePrioMark, Table: int(mark), Mark: mark, NotMark: true, Suppress: -1},
	}
}

var (
	defaultRoute4 = netip.MustParsePrefix("0.0.0.0/0")
	defaultRoute6 = netip.MustParsePrefix("::/0")
	// halfRoutes override the default route without replacing it.
	halfRoutes = []netip.Prefix{
		netip.MustParsePrefix("0.0.0.0/1"),
		netip.MustParsePrefix("128.0.0.0/1"),
		netip.MustParsePrefix("::/1"),
		netip.MustParsePrefix("8000::/1"),
	}
)

// planFullTunnel returns the steps that route the whole host through the
// device, and the steps that undo them in the order they must run.
//
//   - fwmark: table M gets a default route via the device (IPv4 and IPv6) and
//     two rules send everything that does not carry mark M to it, except what a
//     more specific main-table route claims.
//   - pin: a host route per server address through the real gateway, then the
//     four /1 halves via the device.
//
// The undo steps are only those that are not removed with the device anyway,
// plus the routes, so cleanup is symmetric and complete.
func planFullTunnel(rc routingConfig, servers []netip.Addr, rg routeGetter) (ops, undo []netOp, err error) {
	switch rc.Mode {
	case tunRoutingFwmark:
		if err := checkTunMark(rc.Mark); err != nil {
			return nil, nil, err
		}
		for _, fam := range []struct {
			n    int
			dflt netip.Prefix
		}{{4, defaultRoute4}, {6, defaultRoute6}} {
			ops = append(ops, netOp{Kind: opAddTableRoute, Prefix: fam.dflt, Table: int(rc.Mark), Link: rc.Tun, SkipIfUnsupported: fam.n == 6})
		}
		for _, fam := range []int{4, 6} {
			for _, r := range fullTunnelRules(fam, rc.Mark) {
				ops = append(ops, netOp{Kind: opAddRule, Rule: r, SkipIfUnsupported: fam == 6})
			}
		}
	case tunRoutingPin:
		pins, _, err := planPins(servers, rg)
		if err != nil {
			return nil, nil, err
		}
		ops = append(ops, pins...)
		for _, p := range halfRoutes {
			ops = append(ops, netOp{Kind: opAddRoute, Prefix: p, Link: rc.Tun, SkipIfUnsupported: p.Addr().Is6()})
		}
	default:
		return nil, nil, fmt.Errorf("unknown routing mode %q", rc.Mode)
	}
	return ops, undoOps(ops), nil
}

// planPins returns the host routes that keep the tunnel's own traffic on the
// real path to each server, and their undo. It asks rg for the route to every
// server address, so it must run while no pin for those addresses exists.
func planPins(servers []netip.Addr, rg routeGetter) (ops, undo []netOp, err error) {
	if len(servers) == 0 {
		return nil, nil, errors.New("cannot pin routes to the tunnel server: its address is unknown")
	}
	for _, s := range servers {
		s = s.WithZone("").Unmap()
		info, err := rg.RouteGet(s)
		if err != nil {
			return nil, nil, fmt.Errorf("find the route to tunnel server %s: %w", s, err)
		}
		if info.Link == "" {
			return nil, nil, fmt.Errorf("find the route to tunnel server %s: no egress interface", s)
		}
		if info.ExactHost {
			slog.Debug("Server already has a host route; leaving it alone", "server", s, "interface", info.Link)
			continue
		}
		ops = append(ops, netOp{
			Kind:    opAddHostRoute,
			Prefix:  netip.PrefixFrom(s, s.BitLen()),
			Gateway: info.Gateway,
			Link:    info.Link,
		})
	}
	return ops, undoOps(ops), nil
}

// undoOps returns the inverse of the invertible ops in ops, last first.
func undoOps(ops []netOp) []netOp {
	var undo []netOp
	for i := len(ops) - 1; i >= 0; i-- {
		op := ops[i]
		inv := op
		switch op.Kind {
		case opAddRule:
			inv.Kind = opDelRule
		case opAddTableRoute:
			inv.Kind = opDelTableRoute
		case opAddHostRoute:
			inv.Kind = opDelHostRoute
		case opAddRoute:
			inv.Kind = opDelRoute
		default:
			continue
		}
		inv.SkipIfUnsupported = false
		undo = append(undo, inv)
	}
	return undo
}

// routingChoice is the outcome of chooseRouting.
type routingChoice struct {
	Mode string
	// Reason says why the mode was chosen, for the log.
	Reason string
	// Warning is set when the choice rests on something that could not be
	// verified.
	Warning string
}

// chooseRouting resolves the routing option to "fwmark" or "pin".
//
// fwmark is only safe when strict reverse-path filtering is off: the server's
// replies arrive on the egress interface, and a strict check does its reverse
// lookup with mark 0, which matches the rule that sends unmarked traffic to the
// TUN, so the replies are dropped and the session never comes up.
//
// rpFilterFor reports the effective rp_filter for the route to ip: the larger
// of the "all" and the egress-interface settings (the kernel takes the max). It
// is 0 where rp_filter does not apply (IPv6). auto picks fwmark unless some
// server is strict, and treats an unreadable setting as strict (it fails toward
// pin, which works either way). An explicit fwmark with a strict setting is
// refused; with an unreadable one it is allowed with a warning, because the
// operator asked for it and it cannot be shown to fail.
func chooseRouting(requested string, servers []netip.Addr, rpFilterFor func(ip netip.Addr) (int, error)) (routingChoice, error) {
	switch requested {
	case tunRoutingPin:
		return routingChoice{Mode: tunRoutingPin, Reason: "routing=pin"}, nil
	case tunRoutingFwmark, tunRoutingAuto:
	default:
		return routingChoice{}, fmt.Errorf("unknown routing %q", requested)
	}

	var strict, unreadable []netip.Addr
	for _, s := range servers {
		s = s.WithZone("").Unmap()
		v, err := rpFilterFor(s)
		switch {
		case err != nil:
			slog.Debug("Cannot read rp_filter", "server", s, "err", err)
			unreadable = append(unreadable, s)
		case v == rpFilterStrict:
			strict = append(strict, s)
		}
	}

	switch {
	case requested == tunRoutingFwmark && len(strict) > 0:
		return routingChoice{}, fmt.Errorf("routing=fwmark cannot work here: strict reverse-path filtering (rp_filter=1) is active for the route to the tunnel server %s, and it would drop the server's replies; use routing=pin or routing=auto, or relax it with: sysctl -w net.ipv4.conf.all.rp_filter=2 (and the same for the egress interface, whichever is higher counts)", strict[0])
	case requested == tunRoutingFwmark && len(unreadable) > 0:
		return routingChoice{Mode: tunRoutingFwmark, Reason: "routing=fwmark", Warning: "cannot read rp_filter for the route to the tunnel server; if the session never comes up, strict reverse-path filtering may be dropping its replies: use routing=pin"}, nil
	case requested == tunRoutingFwmark:
		return routingChoice{Mode: tunRoutingFwmark, Reason: "routing=fwmark"}, nil
	case len(strict) > 0:
		return routingChoice{Mode: tunRoutingPin, Reason: fmt.Sprintf("strict rp_filter for the route to %s would drop fwmark-routed replies", strict[0])}, nil
	case len(unreadable) > 0:
		return routingChoice{Mode: tunRoutingPin, Reason: fmt.Sprintf("rp_filter for the route to %s is unreadable; assuming strict", unreadable[0])}, nil
	}
	return routingChoice{Mode: tunRoutingFwmark, Reason: "rp_filter is not strict"}, nil
}

// isGoneError reports whether err means the thing an undo step removes is
// already gone. EAFNOSUPPORT is the kernel's answer for an IPv6 rule or route
// on a host without IPv6: there is nothing to remove.
func isGoneError(err error) bool {
	return errors.Is(err, syscall.ESRCH) || errors.Is(err, syscall.ENOENT) ||
		errors.Is(err, syscall.ENODEV) || errors.Is(err, syscall.EADDRNOTAVAIL) ||
		errors.Is(err, syscall.EAFNOSUPPORT)
}

// runUndo applies undo ops, ignoring steps whose target is already gone, and
// returns the remaining failures joined. It never stops early: cleanup must
// remove as much as it can.
func runUndo(undo []netOp, nl netConfigurer) error {
	var errs []error
	for _, op := range undo {
		if err := runNetOp(op, nl); err != nil && !isGoneError(err) {
			errs = append(errs, fmt.Errorf("%s: %w", op.describe(), err))
		}
	}
	return errors.Join(errs...)
}

// uniqueAddrs returns addrs without duplicates, zones or IPv4-mapped forms.
func uniqueAddrs(addrs []netip.Addr) []netip.Addr {
	var out []netip.Addr
	for _, a := range addrs {
		a = a.WithZone("").Unmap()
		if !slices.Contains(out, a) {
			out = append(out, a)
		}
	}
	return out
}

// readRPFilter reads the effective rp_filter of an interface; a variable so
// tests can supply the sysctl values.
var readRPFilter = rpFilterOf

// rpFilterFor returns the lookup chooseRouting needs: the effective rp_filter
// for the route rg reports to an address. IPv6 has no rp_filter sysctl, so it
// reports 0 (not strict).
func rpFilterFor(rg routeGetter) func(ip netip.Addr) (int, error) {
	return func(ip netip.Addr) (int, error) {
		if ip.Is6() {
			return 0, nil
		}
		info, err := rg.RouteGet(ip)
		if err != nil {
			return 0, err
		}
		return readRPFilter(info.Link)
	}
}
