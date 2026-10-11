package client

import (
	"fmt"
	"net/netip"
	"net/url"
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
		case "mtu", "addr", "route", "configure":
		default:
			return nil, fmt.Errorf("unknown tun:// option %q (supported: mtu, addr, route, configure)", key)
		}
	}
	for _, key := range []string{"mtu", "configure"} {
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
		p, err := netip.ParsePrefix(v)
		if err != nil {
			return nil, fmt.Errorf("invalid tun:// route %q: %w", v, err)
		}
		if err := checkNotMapped("route", v, p); err != nil {
			return nil, err
		}
		spec.Routes = append(spec.Routes, p.Masked())
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

func validateTunName(name string) error {
	if len(name) > tunMaxNameLen {
		return fmt.Errorf("tun:// device name %q is longer than %d characters", name, tunMaxNameLen)
	}
	for _, r := range name {
		if r < 0x20 || r == 0x7f {
			return fmt.Errorf("invalid tun:// device name %q: control character %U", name, r)
		}
	}
	if name == "." || name == ".." || strings.ContainsAny(name, "/ ") {
		return fmt.Errorf("invalid tun:// device name %q", name)
	}
	return nil
}
