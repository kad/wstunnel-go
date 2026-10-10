package server

import (
	"net"
	"net/netip"

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
}

func tunDestinationDenied(ip netip.Addr) bool {
	for _, p := range tunDeniedPrefixes {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

// tunFlowAllowed reports whether a tun flow may be forwarded. rule is the
// restriction that admitted the session, or nil when no restrictions are
// configured.
//
// Each flow is checked as if it were a Tcp or Udp forward tunnel to the flow's
// destination IP and port, against the same rule, so CIDR, port and host
// filters keep their existing meaning.
func tunFlowAllowed(rule *RestrictionConfig, f tun.Flow) bool {
	ip := f.Dst.Addr().Unmap()
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
