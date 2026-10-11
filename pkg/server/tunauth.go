package server

import (
	"fmt"
	"net"
	"net/netip"
	"strings"

	"github.com/kad/wstunnel-go/pkg/protocol"
	"github.com/kad/wstunnel-go/pkg/tun"
)

// tunDeniedPrefixes are destinations a tun flow reaches only when the
// restriction that admitted the session names them with a CIDR inside the
// denied prefix.
// Without this, a tun client could reach the server's own loopback services
// or the cloud metadata endpoint.
var tunDeniedPrefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),          // "this network", includes 0.0.0.0
	netip.MustParsePrefix("127.0.0.0/8"),        // loopback
	netip.MustParsePrefix("169.254.0.0/16"),     // link-local, includes 169.254.169.254
	netip.MustParsePrefix("224.0.0.0/4"),        // multicast
	netip.MustParsePrefix("255.255.255.255/32"), // limited broadcast
	netip.MustParsePrefix("::/128"),             // unspecified
	netip.MustParsePrefix("::1/128"),            // loopback
	netip.MustParsePrefix("fe80::/10"),          // link-local
	netip.MustParsePrefix("ff00::/8"),           // multicast
	netip.MustParsePrefix("fd00:ec2::254/128"),  // AWS IPv6 instance metadata

	// Cloud metadata services that do not use 169.254.169.254.
	netip.MustParsePrefix("100.100.100.200/32"), // Alibaba Cloud
	netip.MustParsePrefix("168.63.129.16/32"),   // Azure WireServer
}

// embeddedIPv4 returns the IPv4 address carried inside an IPv6 address in one
// of the forms a NAT64 gateway or a transition mechanism would translate back
// to IPv4: the NAT64 well-known prefix 64:ff9b::/96, 6to4 (2002::/16) and the
// deprecated IPv4-compatible form ::/96.
func embeddedIPv4(ip netip.Addr) (netip.Addr, bool) {
	if !ip.Is6() {
		return netip.Addr{}, false
	}
	b := ip.As16()
	switch {
	case ip.Is4In6():
		return netip.Addr{}, false // handled by Unmap
	case b[0] == 0x00 && b[1] == 0x64 && b[2] == 0xff && b[3] == 0x9b && allZero(b[4:12]):
		return netip.AddrFrom4([4]byte{b[12], b[13], b[14], b[15]}), true
	case b[0] == 0x20 && b[1] == 0x02:
		return netip.AddrFrom4([4]byte{b[2], b[3], b[4], b[5]}), true
	case allZero(b[:12]):
		return netip.AddrFrom4([4]byte{b[12], b[13], b[14], b[15]}), true
	}
	return netip.Addr{}, false
}

func allZero(b []byte) bool {
	for _, v := range b {
		if v != 0 {
			return false
		}
	}
	return true
}

// tunDestinationDenied reports whether ip is on the built-in deny list. An
// address that cannot be classified (invalid) is denied, a zone is ignored, and
// an IPv6 address that embeds a denied IPv4 address is denied too.
func tunDestinationDenied(ip netip.Addr) bool {
	if !ip.IsValid() {
		return true
	}
	ip = ip.WithZone("").Unmap()
	if deniedPrefixContains(ip) {
		return true
	}
	if v4, ok := embeddedIPv4(ip); ok && deniedPrefixContains(v4) {
		return true
	}
	return false
}

func deniedPrefixContains(ip netip.Addr) bool {
	for _, p := range tunDeniedPrefixes {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

// ParseTunAllow parses tun_allow entries: CIDR prefixes, or bare addresses for
// single hosts. Prefixes are masked, and IPv4-mapped IPv6 entries are
// converted to plain IPv4. It reports the first entry that does not parse, so
// the command line and the Caddy module can refuse a bad value at startup.
func ParseTunAllow(entries []string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, e := range entries {
		e = strings.TrimSpace(e)
		var p netip.Prefix
		if strings.Contains(e, "/") {
			var err error
			p, err = netip.ParsePrefix(e)
			if err != nil {
				return nil, fmt.Errorf("tun_allow %q: %w", e, err)
			}
		} else {
			a, err := netip.ParseAddr(e)
			if err != nil {
				return nil, fmt.Errorf("tun_allow %q: want a CIDR or an address", e)
			}
			p = netip.PrefixFrom(a, a.BitLen())
		}
		if p.Addr().Is4In6() && p.Bits() < 96 {
			return nil, fmt.Errorf("tun_allow %q: an IPv4-mapped prefix needs at least 96 bits; write the IPv4 network instead", e)
		}
		p = p.Masked()
		if a := p.Addr(); a.Is4In6() {
			p = netip.PrefixFrom(a.Unmap(), p.Bits()-96)
		}
		out = append(out, p)
	}
	return out, nil
}

// authorizeTunFlow applies the server-wide tun_allow list, if any, and then
// the restriction rule that admitted the session.
func (s *Server) authorizeTunFlow(rule *RestrictionConfig, f tun.Flow) bool {
	if s.tunAllowSet {
		ip := f.Dst.Addr().WithZone("").Unmap()
		allowed := false
		for _, p := range s.tunAllow {
			if p.Contains(ip) {
				allowed = true
				break
			}
		}
		if !allowed {
			return false
		}
	}
	return tunFlowAllowed(rule, f)
}

// tunFlowAllowed reports whether a tun flow may be forwarded. rule is the
// restriction that admitted the session, or nil when no restrictions are
// configured.
//
// Each flow is checked as if it were a Tcp or Udp forward tunnel to the flow's
// destination IP and port, against the same rule, so CIDR, port and host
// filters keep their existing meaning.
func tunFlowAllowed(rule *RestrictionConfig, f tun.Flow) bool {
	ip := f.Dst.Addr().WithZone("").Unmap()
	denied := tunDestinationDenied(ip)
	if rule == nil {
		return !denied
	}

	claims := &protocol.JwtTunnelConfig{Remote: ip.String(), Port: f.Dst.Port()}
	switch f.Network {
	case "tcp":
		claims.Protocol.Tcp = &protocol.TcpProtocol{}
	case "udp":
		claims.Protocol.Udp = &protocol.UdpProtocol{}
	default:
		return false
	}

	for _, a := range rule.Allow {
		if a.Tunnel == nil || !a.Tunnel.Allows(claims) {
			continue
		}
		if !denied || a.Tunnel.namesExplicitly(ip) {
			return true
		}
	}
	return false
}

// namesExplicitly reports whether one of the CIDRs lifts the deny list for
// ip: the CIDR must lie entirely inside a denied prefix that contains ip.
// A broad CIDR such as 0.0.0.0/1, 128.0.0.0/1 or ::/0 therefore lifts nothing,
// while 127.0.0.1/32 and 127.0.0.0/8 lift loopback.
//
// An address denied only because it embeds a denied IPv4 address (NAT64, 6to4,
// IPv4-compatible) is contained by no denied prefix, so no CIDR can lift it.
func (at *AllowTunnelConfig) namesExplicitly(ip netip.Addr) bool {
	for _, d := range tunDeniedPrefixes {
		if !d.Contains(ip) {
			continue
		}
		for _, c := range at.CIDR {
			p, ok := ipNetPrefix(c.IPNet)
			if ok && d.Contains(p.Addr()) && p.Bits() >= d.Bits() {
				return true
			}
		}
	}
	return false
}

// ipNetPrefix converts n to a netip.Prefix. IPv4 networks held in 16-byte form
// (with a /96 or longer mask) are unmapped so they compare with IPv4 prefixes.
func ipNetPrefix(n *net.IPNet) (netip.Prefix, bool) {
	if n == nil {
		return netip.Prefix{}, false
	}
	addr, ok := netip.AddrFromSlice(n.IP)
	if !ok {
		return netip.Prefix{}, false
	}
	ones, bits := n.Mask.Size()
	if bits == 0 {
		return netip.Prefix{}, false // non-canonical mask
	}
	if addr.Is4In6() && bits == 128 && ones >= 96 {
		addr, ones = addr.Unmap(), ones-96
	}
	p := netip.PrefixFrom(addr, ones)
	if !p.IsValid() {
		return netip.Prefix{}, false
	}
	return p.Masked(), true
}

// normalizeTunClaims discards the client-supplied destination of a tun claim.
// A tun session has no single destination, so the server evaluates restrictions
// against the fixed placeholder 0.0.0.0:0 whatever the client put in r and rp;
// each flow is authorized separately by tunFlowAllowed.
func normalizeTunClaims(claims *protocol.JwtTunnelConfig) {
	if claims.Protocol.Tun != nil {
		claims.Remote = "0.0.0.0"
		claims.Port = 0
	}
}
