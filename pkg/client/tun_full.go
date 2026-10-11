package client

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os/exec"
	"strconv"
	"sync"
	"syscall"

	"github.com/kad/wstunnel-go/internal/socket"
)

// tunDeps are the host interactions of StartTun. Production uses the kernel;
// tests substitute a recording configurer, an in-memory device and a fake
// resolvectl.
type tunDeps struct {
	openDevice func(name string) (tunDevice, error)
	deviceMTU  func(name string) (int, error)
	nl         netConfigurer
	lookPath   func(file string) (string, error)
	runCmd     func(ctx context.Context, name string, args ...string) error
}

func defaultTunDeps() tunDeps {
	return tunDeps{
		openDevice: openTunDevice,
		deviceMTU:  deviceMTU,
		nl:         newNetConfigurer(),
		lookPath:   exec.LookPath,
		runCmd: func(ctx context.Context, name string, args ...string) error {
			out, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
			if err != nil {
				return fmt.Errorf("%w: %s", err, out)
			}
			return nil
		},
	}
}

// markedDialer returns a Dial function for net.Resolver whose sockets carry
// mark, so DNS queries made by the client itself take the fwmark bypass rather
// than the tunnel. setMark is socket.SetSoMark in production.
func markedDialer(mark uint32, setMark func(fd uintptr, mark uint32) error) func(ctx context.Context, network, address string) (net.Conn, error) {
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		d := net.Dialer{
			Control: func(_, _ string, rc syscall.RawConn) error {
				var serr error
				if err := rc.Control(func(fd uintptr) { serr = setMark(fd, mark) }); err != nil {
					return err
				}
				return serr
			},
		}
		return d.DialContext(ctx, network, address)
	}
}

// markedResolver is a pure-Go resolver (the cgo one would ignore Dial) whose
// sockets carry mark.
func markedResolver(mark uint32, setMark func(fd uintptr, mark uint32) error) *net.Resolver {
	return &net.Resolver{PreferGo: true, Dial: markedDialer(mark, setMark)}
}

// lookupHost resolves host with the client's resolver: the marked one in a
// fwmark full tunnel, else the system resolver.
func (c *Client) lookupHost(ctx context.Context, host string) ([]netip.Addr, error) {
	if r := c.resolver.Load(); r != nil {
		return r.LookupNetIP(ctx, "ip", host)
	}
	return lookupNetIP(ctx, host)
}

// resolveUDPAddr is net.ResolveUDPAddr that honours the client's resolver.
func (c *Client) resolveUDPAddr(ctx context.Context, addr string) (*net.UDPAddr, error) {
	r := c.resolver.Load()
	if r == nil {
		return net.ResolveUDPAddr("udp", addr)
	}
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return nil, err
	}
	if ip, err := netip.ParseAddr(host); err == nil {
		return net.UDPAddrFromAddrPort(netip.AddrPortFrom(ip, uint16(port))), nil
	}
	ips, err := r.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return nil, err
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("resolve %q: no addresses", host)
	}
	return net.UDPAddrFromAddrPort(netip.AddrPortFrom(ips[0], uint16(port))), nil
}

// staleRules selects, from the rules that exist, the ones a crashed full
// tunnel may have left: the suppress rule at our priority whatever the mark, and
// the catch-all rule at our priority for our mark.
func staleRules(existing []ruleSpec, mark uint32) []ruleSpec {
	var stale []ruleSpec
	for _, r := range existing {
		switch {
		case r.Priority == rulePrioSuppress && r.Suppress == 0 && r.Table == 254 && !r.NotMark:
			stale = append(stale, r)
		case r.Priority == rulePrioMark && r.NotMark && r.Table == int(mark) && r.Mark == mark:
			stale = append(stale, r)
		}
	}
	return stale
}

// purgeStaleRules deletes leftovers of a previous full tunnel, so installing
// ours does not collide with them. A stale rule is harmless on its own (its
// table is empty, lookups fall through to main), which is why a crash cannot
// black-hole the host; this keeps the rule list from growing.
func purgeStaleRules(nl netConfigurer, mark uint32) error {
	var errs []error
	for _, family := range []int{4, 6} {
		existing, err := nl.ListRules(family)
		if err != nil {
			if isUnsupportedError(err) {
				continue
			}
			errs = append(errs, fmt.Errorf("list ipv%d rules: %w", family, err))
			continue
		}
		for _, r := range staleRules(existing, mark) {
			// A duplicate can exist; delete until the kernel says none is left.
			for range 16 {
				err := nl.DelRule(r)
				if err != nil {
					if !isGoneError(err) {
						errs = append(errs, fmt.Errorf("delete stale rule %s: %w", r, err))
					}
					break
				}
				slog.Warn("Removed a stale rule left by an earlier run", "rule", r.String())
			}
		}
	}
	return errors.Join(errs...)
}

// pinSet owns the host routes that keep the tunnel's own traffic on the real
// path in pin mode. They are rebuilt before every connect, because the real
// gateway can change while the client runs and the server can resolve to new
// addresses.
type pinSet struct {
	mu   sync.Mutex
	nl   netConfigurer
	tun  string
	undo []netOp
}

// refresh removes the previous pins, looks the real route up again for every
// server address (ignoring the tunnel's own routes, which would otherwise
// answer) and installs new pins. If it fails the pins stay removed: the
// server is then reachable only through the tunnel, so nothing leaks, and the
// next attempt tries again.
func (p *pinSet) refresh(servers []netip.Addr) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if err := runUndo(p.undo, p.nl); err != nil {
		slog.Warn("Could not remove the previous server route pins", "err", err)
	}
	p.undo = nil

	ops, undo, err := planPins(uniqueAddrs(servers), routeGetFunc(func(ip netip.Addr) (routeInfo, error) {
		return p.nl.RouteGet(ip, p.tun)
	}))
	if err != nil {
		return err
	}
	p.undo = undo // record before applying: a partial install must still be removed
	return applyNetOps(p.tun, ops, p.nl)
}

// clear removes the current pins.
func (p *pinSet) clear() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	err := runUndo(p.undo, p.nl)
	p.undo = nil
	return err
}

// configureDNS points the device's resolver at the given servers through
// systemd-resolved, and routes every domain there. /etc/resolv.conf is never
// edited. Without resolvectl it only warns.
func configureDNS(ctx context.Context, deps tunDeps, ifname string, servers []netip.Addr) (revert func() error) {
	if len(servers) == 0 {
		return func() error { return nil }
	}
	path, err := deps.lookPath("resolvectl")
	if err != nil {
		slog.Warn("dns= was requested but resolvectl is not installed; DNS settings were not changed. Point your resolver at the servers yourself", "dns", servers)
		return func() error { return nil }
	}
	args := []string{"dns", ifname}
	for _, s := range servers {
		args = append(args, s.String())
	}
	if err := deps.runCmd(ctx, path, args...); err != nil {
		slog.Warn("resolvectl dns failed; DNS settings were not changed", "err", err)
		return func() error { return nil }
	}
	if err := deps.runCmd(ctx, path, "domain", ifname, "~."); err != nil {
		slog.Warn("resolvectl domain failed; the DNS servers are set but not used for all names", "err", err)
	}
	return func() error {
		// systemd-resolved forgets the settings when the link goes away; revert
		// explicitly for the case where it did not (a device that outlives us).
		if err := deps.runCmd(context.WithoutCancel(ctx), path, "revert", ifname); err != nil {
			slog.Debug("resolvectl revert failed (the link is probably gone already)", "err", err)
		}
		return nil
	}
}

// fullTunnel is the routing state of a route=default tunnel.
type fullTunnel struct {
	rc      routingConfig
	servers []netip.Addr
	choice  routingChoice
	pins    *pinSet // pin mode only
}

// prepareFullTunnel decides the routing mode, clears leftovers of a crashed
// run and arms the client's own sockets, before any device exists. A refusal
// here (explicit fwmark with strict rp_filter) leaves the host untouched.
func (c *Client) prepareFullTunnel(spec *TunSpec, servers []netip.Addr, deps tunDeps) (*fullTunnel, error) {
	if c.pool != nil {
		return nil, errors.New("tun:// route=default cannot be combined with connection_min_idle: pooled connections are opened before the routing is in place and would be cut off; remove connection_min_idle")
	}
	servers = uniqueAddrs(servers)
	rg := routeGetFunc(func(ip netip.Addr) (routeInfo, error) { return deps.nl.RouteGet(ip, "") })
	choice, err := chooseRouting(spec.Routing, servers, rpFilterFor(rg))
	if err != nil {
		return nil, err
	}
	mark := tunMark(c.Config.SocketSoMark)
	if choice.Mode == tunRoutingFwmark {
		if err := checkTunMark(mark); err != nil {
			return nil, err
		}
	}
	slog.Info("Full tunnel routing", "mode", choice.Mode, "why", choice.Reason, "mark", mark)
	if choice.Warning != "" {
		slog.Warn(choice.Warning)
	}
	if err := purgeStaleRules(deps.nl, mark); err != nil {
		return nil, fmt.Errorf("clear rules left by an earlier run: %w", err)
	}

	ft := &fullTunnel{rc: routingConfig{Mode: choice.Mode, Mark: mark}, servers: servers, choice: choice}
	if choice.Mode == tunRoutingFwmark {
		// The client's own sockets and DNS lookups must carry the mark, even if
		// the operator did not ask for --socket-so-mark.
		c.fullTunnelMark.Store(mark)
		c.resolver.Store(markedResolver(mark, socket.SetSoMark))
	}
	return ft, nil
}

// install adds the routing for device ifname and returns the cleanup that
// removes it. On failure it removes whatever it had added.
func (ft *fullTunnel) install(ifname string, nl netConfigurer) (cleanup func() error, err error) {
	ft.rc.Tun = ifname
	rg := routeGetFunc(func(ip netip.Addr) (routeInfo, error) { return nl.RouteGet(ip, ifname) })
	ops, undo, err := planFullTunnel(ft.rc, ft.servers, rg)
	if err != nil {
		return nil, err
	}
	if ft.rc.Mode == tunRoutingPin {
		ft.pins = &pinSet{nl: nl, tun: ifname}
		// The static pins from planFullTunnel belong to the pin set from now on,
		// so a refresh replaces them instead of leaving them behind.
		nPins := 0
		for _, op := range ops {
			if op.Kind == opAddHostRoute {
				nPins++
			}
		}
		ft.pins.undo = undoOps(ops[:nPins])
		undo = undoOps(ops[nPins:])
	}
	cleanup = func() error {
		// Reverse of the installation order: the halves first, then the pins.
		errs := []error{runUndo(undo, nl)}
		if ft.pins != nil {
			errs = append(errs, ft.pins.clear())
		}
		return errors.Join(errs...)
	}
	if err := applyNetOps(ifname, ops, nl); err != nil {
		if cerr := cleanup(); cerr != nil {
			slog.Warn("Cleanup after a failed full-tunnel setup was incomplete", "err", cerr)
		}
		return nil, err
	}
	return cleanup, nil
}
