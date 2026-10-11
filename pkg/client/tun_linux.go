//go:build linux

package client

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

const tunClonePath = "/dev/net/tun"

// linuxTun is a TUN device read and written one packet at a time. It does not
// negotiate virtio offloads (GSO/GRO): that is faster but needs
// CAP_NET_ADMIN to set the MTU, which would break attaching to a persistent
// device as an unprivileged user.
type linuxTun struct {
	f    *os.File
	name string
	rbuf []byte
}

// openTunDevice creates the TUN device name, or attaches to an existing
// persistent one. An empty name lets the kernel pick tunN.
func openTunDevice(name string) (tunDevice, error) {
	fd, err := unix.Open(tunClonePath, unix.O_RDWR|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", tunClonePath, err)
	}
	ifr, err := unix.NewIfreq(name)
	if err != nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("tun device name %q: %w", name, err)
	}
	ifr.SetUint16(unix.IFF_TUN | unix.IFF_NO_PI)
	if err := unix.IoctlIfreq(fd, unix.TUNSETIFF, ifr); err != nil {
		_ = unix.Close(fd)
		return nil, describeTunOpenError(name, err)
	}
	if err := unix.SetNonblock(fd, true); err != nil {
		_ = unix.Close(fd)
		return nil, err
	}
	return &linuxTun{
		f:    os.NewFile(uintptr(fd), tunClonePath),
		name: ifr.Name(),
		rbuf: make([]byte, 65536),
	}, nil
}

// describeTunOpenError explains a failed TUNSETIFF in terms of what to do.
func describeTunOpenError(name string, err error) error {
	switch {
	case errors.Is(err, unix.EBUSY):
		return fmt.Errorf("tun device %q is already attached by another process: %w (a persistent device can be used by one process at a time; stop the other one or use another device)", name, err)
	case errors.Is(err, unix.EPERM), errors.Is(err, unix.EACCES):
		return fmt.Errorf("cannot create or attach tun device %q: %w (creating a device needs CAP_NET_ADMIN; as an unprivileged user attach to a persistent one: ip tuntap add mode tun user $USER name NAME, then use tun://NAME?configure=false)", name, err)
	}
	return fmt.Errorf("create tun device %q: %w", name, err)
}

func (t *linuxTun) Name() string { return t.name }

// ReadPacket returns one IP packet; it is valid until the next call.
func (t *linuxTun) ReadPacket() ([]byte, error) {
	n, err := t.f.Read(t.rbuf)
	if err != nil {
		return nil, err
	}
	return t.rbuf[:n], nil
}

func (t *linuxTun) WritePacket(p []byte) error {
	_, err := t.f.Write(p)
	return err
}

// Close unblocks a pending ReadPacket and removes the device if it was not
// persistent.
func (t *linuxTun) Close() error { return t.f.Close() }

// deviceMTU reports the current MTU of ifname.
func deviceMTU(ifname string) (int, error) {
	iface, err := net.InterfaceByName(ifname)
	if err != nil {
		return 0, err
	}
	return iface.MTU, nil
}

// linkByName is netlink.LinkByName with a missing link reported as ENODEV, so
// cleanup can tell "already gone" from a real failure.
func linkByName(name string) (netlink.Link, error) {
	link, err := netlink.LinkByName(name)
	var notFound netlink.LinkNotFoundError
	if errors.As(err, &notFound) {
		return nil, fmt.Errorf("%w: %v", unix.ENODEV, err)
	}
	return link, err
}

func newNetConfigurer() netConfigurer { return netlinkConfigurer{} }

type netlinkConfigurer struct{}

func ipNet(p netip.Prefix) *net.IPNet {
	return &net.IPNet{
		IP:   net.IP(p.Addr().AsSlice()),
		Mask: net.CIDRMask(p.Bits(), p.Addr().BitLen()),
	}
}

func (netlinkConfigurer) SetMTU(ifname string, mtu int) error {
	link, err := linkByName(ifname)
	if err != nil {
		return err
	}
	return netlink.LinkSetMTU(link, mtu)
}

func (netlinkConfigurer) AddAddr(ifname string, p netip.Prefix) error {
	link, err := linkByName(ifname)
	if err != nil {
		return err
	}
	return netlink.AddrAdd(link, &netlink.Addr{IPNet: ipNet(p)})
}

func (netlinkConfigurer) LinkUp(ifname string) error {
	link, err := linkByName(ifname)
	if err != nil {
		return err
	}
	return netlink.LinkSetUp(link)
}

func (netlinkConfigurer) AddRoute(ifname string, dst netip.Prefix) error {
	link, err := linkByName(ifname)
	if err != nil {
		return err
	}
	return netlink.RouteAdd(&netlink.Route{
		LinkIndex: link.Attrs().Index,
		Dst:       ipNet(dst),
		Scope:     netlink.SCOPE_LINK,
	})
}

func (netlinkConfigurer) DelRoute(ifname string, dst netip.Prefix) error {
	link, err := linkByName(ifname)
	if err != nil {
		return err
	}
	return netlink.RouteDel(&netlink.Route{
		LinkIndex: link.Attrs().Index,
		Dst:       ipNet(dst),
		Scope:     netlink.SCOPE_LINK,
	})
}

func (netlinkConfigurer) tableRoute(ifname string, dst netip.Prefix, table int) (*netlink.Route, error) {
	link, err := linkByName(ifname)
	if err != nil {
		return nil, err
	}
	return &netlink.Route{
		LinkIndex: link.Attrs().Index,
		Dst:       ipNet(dst),
		Scope:     netlink.SCOPE_LINK,
		Table:     table,
	}, nil
}

func (n netlinkConfigurer) AddTableRoute(ifname string, dst netip.Prefix, table int) error {
	r, err := n.tableRoute(ifname, dst, table)
	if err != nil {
		return err
	}
	return netlink.RouteAdd(r)
}

func (n netlinkConfigurer) DelTableRoute(ifname string, dst netip.Prefix, table int) error {
	r, err := n.tableRoute(ifname, dst, table)
	if err != nil {
		return err
	}
	return netlink.RouteDel(r)
}

func hostRoute(dst netip.Prefix, gw netip.Addr, linkName string) (*netlink.Route, error) {
	link, err := linkByName(linkName)
	if err != nil {
		return nil, err
	}
	r := &netlink.Route{LinkIndex: link.Attrs().Index, Dst: ipNet(dst), Scope: netlink.SCOPE_LINK}
	if gw.IsValid() {
		r.Gw = net.IP(gw.AsSlice())
		r.Scope = netlink.SCOPE_UNIVERSE
	}
	return r, nil
}

func (netlinkConfigurer) AddHostRoute(dst netip.Prefix, gw netip.Addr, link string) error {
	r, err := hostRoute(dst, gw, link)
	if err != nil {
		return err
	}
	// Replace, not add: a pin left by a crashed run, or by the previous attempt
	// whose removal failed, must not make the new one fail with EEXIST.
	return netlink.RouteReplace(r)
}

func (netlinkConfigurer) DelHostRoute(dst netip.Prefix, gw netip.Addr, link string) error {
	r, err := hostRoute(dst, gw, link)
	if err != nil {
		return err
	}
	return netlink.RouteDel(r)
}

func toNetlinkRule(r ruleSpec) *netlink.Rule {
	nr := netlink.NewRule()
	nr.Family = netlink.FAMILY_V4
	if r.Family == 6 {
		nr.Family = netlink.FAMILY_V6
	}
	nr.Priority = r.Priority
	nr.Table = r.Table
	if r.NotMark {
		mask := ^uint32(0)
		nr.Mark = r.Mark
		nr.Mask = &mask
		nr.Invert = true
	}
	nr.SuppressPrefixlen = r.Suppress
	return nr
}

func (netlinkConfigurer) ListRules(family int) ([]ruleSpec, error) {
	fam := netlink.FAMILY_V4
	if family == 6 {
		fam = netlink.FAMILY_V6
	}
	rules, err := netlink.RuleList(fam)
	if err != nil {
		return nil, err
	}
	out := make([]ruleSpec, 0, len(rules))
	for _, r := range rules {
		out = append(out, ruleSpec{
			Family:   family,
			Priority: r.Priority,
			Table:    r.Table,
			Mark:     r.Mark,
			NotMark:  r.Invert && (r.Mark != 0 || r.Mask != nil),
			Suppress: r.SuppressPrefixlen,
		})
	}
	return out, nil
}

func (netlinkConfigurer) AddRule(r ruleSpec) error { return netlink.RuleAdd(toNetlinkRule(r)) }
func (netlinkConfigurer) DelRule(r ruleSpec) error { return netlink.RuleDel(toNetlinkRule(r)) }

// RouteGet finds the best main-table route to ip that does not go through
// avoidLink. The kernel's own lookup (ip route get) cannot be used for this:
// once the tunnel's /1 routes exist it answers with the tunnel, which is
// exactly the path being avoided.
func (netlinkConfigurer) RouteGet(ip netip.Addr, avoidLink string) (routeInfo, error) {
	avoidIdx := 0
	if avoidLink != "" {
		if l, err := linkByName(avoidLink); err == nil {
			avoidIdx = l.Attrs().Index
		}
	}
	family := netlink.FAMILY_V4
	if ip.Is6() {
		family = netlink.FAMILY_V6
	}
	routes, err := netlink.RouteListFiltered(family, &netlink.Route{Table: unix.RT_TABLE_MAIN}, netlink.RT_FILTER_TABLE)
	if err != nil {
		return routeInfo{}, err
	}
	var best *netlink.Route
	bestBits := -1
	var bestIdx int
	var bestGw net.IP
	for i := range routes {
		r := &routes[i]
		if r.Type != unix.RTN_UNICAST {
			continue
		}
		idx, gw := r.LinkIndex, r.Gw
		if len(r.MultiPath) > 0 {
			idx, gw = r.MultiPath[0].LinkIndex, r.MultiPath[0].Gw
		}
		if idx == 0 || idx == avoidIdx {
			continue
		}
		bits := 0
		if r.Dst != nil {
			base, ok := netip.AddrFromSlice(r.Dst.IP)
			if !ok {
				continue
			}
			ones, _ := r.Dst.Mask.Size()
			if base.Is4In6() {
				base = base.Unmap()
				ones -= 96
			}
			if ones < 0 || !netip.PrefixFrom(base, ones).Contains(ip) {
				continue
			}
			bits = ones
		}
		if bits > bestBits || (bits == bestBits && r.Priority < best.Priority) {
			best, bestBits, bestIdx, bestGw = r, bits, idx, gw
		}
	}
	if best == nil {
		return routeInfo{}, fmt.Errorf("no route to %s", ip)
	}
	link, err := netlink.LinkByIndex(bestIdx)
	if err != nil {
		return routeInfo{}, err
	}
	info := routeInfo{Link: link.Attrs().Name}
	if gw, ok := netip.AddrFromSlice(bestGw); ok {
		info.Gateway = gw.Unmap()
	}
	if src, ok := netip.AddrFromSlice(best.Src); ok {
		info.Src = src.Unmap()
	}
	return info, nil
}

// rpFilterOf reads the effective rp_filter for traffic arriving on ifname: the
// larger of the "all" and per-interface settings, as the kernel does.
func rpFilterOf(ifname string) (int, error) {
	read := func(scope string) (int, error) {
		b, err := os.ReadFile("/proc/sys/net/ipv4/conf/" + scope + "/rp_filter")
		if err != nil {
			return 0, err
		}
		return strconv.Atoi(strings.TrimSpace(string(b)))
	}
	all, err := read("all")
	if err != nil {
		return 0, err
	}
	dev, err := read(ifname)
	if err != nil {
		return 0, err
	}
	return max(all, dev), nil
}
