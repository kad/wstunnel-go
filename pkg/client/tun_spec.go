package client

import (
	"fmt"
	"net/netip"
	"net/url"
	"slices"
	"strconv"
	"strings"
)

const (
	tunScheme     = "tun://"
	tunDefaultMTU = 1500
	tunMinMTU     = 1280
	tunMaxMTU     = 65535
	// tunMaxNameLen is IFNAMSIZ-1: the longest interface name Linux accepts.
	tunMaxNameLen = 15

	tunRouteDefault  = "default"
	tunRoutingAuto   = "auto"
	tunRoutingFwmark = "fwmark"
	tunRoutingPin    = "pin"
)

var (
	// The defaults sit in the RFC 2544 benchmarking range (198.18.0.0/15) and
	// the ULA range, so they are unlikely to collide with a real network.
	defaultTunAddr4 = netip.MustParsePrefix("198.18.0.1/32")
	defaultTunAddr6 = netip.MustParsePrefix("fd77:7473::1/128")
)

// TunSpec describes one tun:// tunnel: the local TUN device and how it is
// configured.
type TunSpec struct {
	// Name is the interface name; empty lets the kernel pick tunN.
	Name string
	// MTU is the device MTU, sent to the server in the Tun claim.
	MTU uint16
	// Addrs are assigned to the device. When the operator gave none, Addrs
	// holds the IPv4 and IPv6 defaults and DefaultAddrs is true.
	Addrs        []netip.Prefix
	DefaultAddrs bool
	// Routes are installed via the device.
	Routes []netip.Prefix
	// FullTunnel is route=default: all IPv4 and IPv6 traffic goes through the
	// device. Routes is empty then.
	FullTunnel bool
	// Routing selects how a full tunnel keeps the tunnel's own traffic out of
	// the device: "auto", "fwmark" or "pin". Empty unless FullTunnel.
	Routing string
	// DNS are resolvers to configure for the device (full tunnel only).
	DNS []netip.Addr
	// Configure is false when attaching to an existing persistent device whose
	// addresses, MTU and routes are managed elsewhere.
	Configure bool
}

// IsTunArg reports whether a -L argument is a tun:// packet tunnel. The scheme
// match is case-sensitive, like the other tunnel schemes: TUN://x is not a tun
// tunnel.
func IsTunArg(arg string) bool {
	return strings.HasPrefix(arg, tunScheme)
}

// ParseTunArg parses tun://[name]?mtu=N&addr=PREFIX&route=PREFIX&configure=BOOL.
// addr and route may be repeated and accept IPv4 or IPv6 prefixes.
func ParseTunArg(arg string) (*TunSpec, error) {
	if !IsTunArg(arg) {
		return nil, fmt.Errorf("not a tun:// tunnel: %q", arg)
	}
	name, query, _ := strings.Cut(strings.TrimPrefix(arg, tunScheme), "?")
	values, err := url.ParseQuery(query)
	if err != nil {
		return nil, fmt.Errorf("invalid tun:// options: %w", err)
	}
	for key := range values {
		switch key {
		case "mtu", "addr", "route", "configure", "routing", "dns":
		default:
			return nil, fmt.Errorf("unknown tun:// option %q (supported: mtu, addr, route, configure, routing, dns)", key)
		}
	}
	for _, key := range []string{"mtu", "configure", "routing"} {
		if len(values[key]) > 1 {
			return nil, fmt.Errorf("tun:// option %q given more than once", key)
		}
		if values.Has(key) && values.Get(key) == "" {
			return nil, fmt.Errorf("tun:// option %q is empty; give a value or leave it out", key)
		}
	}
	if err := validateTunName(name); err != nil {
		return nil, err
	}

	spec := &TunSpec{Name: name, MTU: tunDefaultMTU, Configure: true}

	if v := values.Get("mtu"); v != "" {
		mtu, err := strconv.ParseUint(v, 10, 16)
		if err != nil || mtu < tunMinMTU {
			return nil, fmt.Errorf("invalid tun:// mtu %q: want %d..%d", v, tunMinMTU, tunMaxMTU)
		}
		spec.MTU = uint16(mtu)
	}
	if v := values.Get("configure"); v != "" {
		configure, err := strconv.ParseBool(v)
		if err != nil {
			return nil, fmt.Errorf("invalid tun:// configure %q: want true or false", v)
		}
		spec.Configure = configure
	}
	for _, v := range values["addr"] {
		p, err := netip.ParsePrefix(v)
		if err != nil {
			return nil, fmt.Errorf("invalid tun:// addr %q: %w", v, err)
		}
		if err := checkNotMapped("addr", v, p); err != nil {
			return nil, err
		}
		if p.Bits() == 0 {
			return nil, fmt.Errorf("invalid tun:// addr %q: a /0 would route every address into the device; use a host prefix (/32 or /128)", v)
		}
		spec.Addrs = append(spec.Addrs, p)
	}
	for _, v := range values["route"] {
		if v == tunRouteDefault {
			spec.FullTunnel = true
			continue
		}
		p, err := netip.ParsePrefix(v)
		if err != nil {
			return nil, fmt.Errorf("invalid tun:// route %q: %w", v, err)
		}
		if err := checkNotMapped("route", v, p); err != nil {
			return nil, err
		}
		spec.Routes = append(spec.Routes, p.Masked())
	}

	if spec.FullTunnel {
		if len(spec.Routes) > 0 || len(values["route"]) > 1 {
			return nil, fmt.Errorf("tun:// route=default cannot be combined with other route= values")
		}
		if !spec.Configure {
			return nil, fmt.Errorf("tun:// route=default is not valid with configure=false: the client has to install the rules and routes itself")
		}
		spec.Routing = tunRoutingAuto
	}
	if v := values.Get("routing"); v != "" {
		if !spec.FullTunnel {
			return nil, fmt.Errorf("tun:// routing=%s is only valid with route=default", v)
		}
		switch v {
		case tunRoutingAuto, tunRoutingFwmark, tunRoutingPin:
			spec.Routing = v
		default:
			return nil, fmt.Errorf("invalid tun:// routing %q: want auto, fwmark or pin", v)
		}
	}
	if values.Has("dns") {
		if !spec.Configure {
			return nil, fmt.Errorf("tun:// dns has no effect with configure=false; configure the device yourself")
		}
		if !spec.FullTunnel {
			return nil, fmt.Errorf("tun:// dns is only valid with route=default (it makes the tunnel the default resolver path)")
		}
		for _, v := range values["dns"] {
			a, err := parseTunDNS(v)
			if err != nil {
				return nil, err
			}
			if !slices.Contains(spec.DNS, a) {
				spec.DNS = append(spec.DNS, a)
			}
		}
	}

	if !spec.Configure {
		if len(spec.Addrs) > 0 || len(spec.Routes) > 0 {
			return nil, fmt.Errorf("tun:// addr and route have no effect with configure=false; configure the device yourself")
		}
		if name == "" {
			return nil, fmt.Errorf("tun:// configure=false needs the name of an existing device, e.g. tun://wst0?configure=false")
		}
		return spec, nil
	}
	if len(spec.Addrs) == 0 {
		spec.Addrs = []netip.Prefix{defaultTunAddr4, defaultTunAddr6}
		spec.DefaultAddrs = true
	}
	return spec, nil
}

// checkNotMapped refuses IPv4-mapped IPv6 prefixes (::ffff:a.b.c.d/N). The
// kernel does not route them as IPv4, so they would not do what they appear to.
func checkNotMapped(kind, raw string, p netip.Prefix) error {
	if p.Addr().Is4In6() {
		return fmt.Errorf("invalid tun:// %s %q: IPv4-mapped IPv6 prefixes are not supported; write the IPv4 prefix instead", kind, raw)
	}
	return nil
}

func parseTunDNS(v string) (netip.Addr, error) {
	a, err := netip.ParseAddr(v)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("invalid tun:// dns %q: want an IP address", v)
	}
	switch {
	case a.Zone() != "":
		return netip.Addr{}, fmt.Errorf("invalid tun:// dns %q: an address with a zone is not supported", v)
	case a.Is4In6(), a.IsUnspecified(), a.IsMulticast():
		return netip.Addr{}, fmt.Errorf("invalid tun:// dns %q: want a unicast IPv4 or IPv6 address", v)
	}
	return a, nil
}

func validateTunName(name string) error {
	if len(name) > tunMaxNameLen {
		return fmt.Errorf("tun:// device name %q is longer than %d characters", name, tunMaxNameLen)
	}
	for _, r := range name {
		if r < 0x20 || r == 0x7f {
			return fmt.Errorf("invalid tun:// device name %q: control character %U", name, r)
		}
	}
	if strings.HasPrefix(name, "-") {
		// Would be read as an option by the tools the name is handed to
		// (resolvectl, ip), and the kernel does not give such names a meaning.
		return fmt.Errorf("invalid tun:// device name %q: must not start with '-'", name)
	}
	if name == "." || name == ".." || strings.ContainsAny(name, "/: ") {
		return fmt.Errorf("invalid tun:// device name %q", name)
	}
	return nil
}
