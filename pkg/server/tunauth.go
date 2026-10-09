package server

import (
	"net"
	"net/netip"

	"github.com/kad/wstunnel-go/pkg/protocol"
	"github.com/kad/wstunnel-go/pkg/tun"
)

// tunDeniedPrefixes are destinations a tun flow reaches only when the
// restriction that admitted the session names them with a specific CIDR.
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

// namesExplicitly reports whether one of the CIDRs contains ip with a non-zero
// prefix length. 0.0.0.0/0 and ::/0 match everything and so do not count.
func (at *AllowTunnelConfig) namesExplicitly(ip netip.Addr) bool {
	for _, c := range at.CIDR {
		if c.IPNet == nil {
			continue
		}
		if ones, _ := c.Mask.Size(); ones > 0 && c.Contains(net.IP(ip.AsSlice())) {
			return true
		}
	}
	return false
}
