package server

import (
	"net/netip"
	"testing"
)

func TestTunDestinationDeniedExtras(t *testing.T) {
	for _, tc := range []struct {
		dst  string
		want bool
		why  string
	}{
		// Cloud metadata services beyond 169.254.169.254.
		{"100.100.100.200", true, "Alibaba Cloud metadata"},
		{"168.63.129.16", true, "Azure WireServer"},
		{"100.100.100.201", false, "neighbouring address is not metadata"},
		{"168.63.129.17", false, "neighbouring address is not metadata"},

		// NAT64 well-known prefix 64:ff9b::/96 carries an IPv4 address.
		{"64:ff9b::7f00:1", true, "NAT64 of 127.0.0.1"},
		{"64:ff9b::a9fe:a9fe", true, "NAT64 of 169.254.169.254"},
		{"64:ff9b::6464:64c8", true, "NAT64 of 100.100.100.200"},
		{"64:ff9b::808:808", false, "NAT64 of 8.8.8.8"},

		// Local-use NAT64 prefix 64:ff9b:1::/48 (RFC 8215): the operator picks
		// the prefix length, so the IPv4 address sits where RFC 6052 puts it
		// for /48, /56, /64 or /96 and every reading is checked.
		{"64:ff9b:1::7f00:1", true, "local-use NAT64 /96 of 127.0.0.1"},
		{"64:ff9b:1:7f00:0:100::", true, "local-use NAT64 /48 of 127.0.0.1 (octets 6, 7, 9, 10)"},
		{"64:ff9b:1:a9fe:a9:fe00::", true, "local-use NAT64 /48 of 169.254.169.254"},
		{"64:ff9b:1:7f:0:1::", true, "local-use NAT64 /56 of 127.0.0.1 (octets 7, 9, 10, 11)"},
		{"64:ff9b:1:0:a9:fea9:fe00:0", true, "local-use NAT64 /64 of 169.254.169.254"},
		{"64:ff9b:1::808:808", false, "local-use NAT64 of 8.8.8.8 stays allowed"},
		{"64:ff9b:2::7f00:1", false, "64:ff9b:2:: is outside the local-use /48"},

		// ISATAP embeds an IPv4 address after a 0000:5efe or 0200:5efe
		// interface identifier under any /64.
		{"2001:db8::5efe:7f00:1", true, "ISATAP of 127.0.0.1"},
		{"2001:db8::200:5efe:a9fe:a9fe", true, "ISATAP (global scope) of 169.254.169.254"},
		{"2001:db8::5efe:808:808", false, "ISATAP of 8.8.8.8"},
		{"2001:db8::1:5efe:7f00:1", false, "not an ISATAP identifier (bytes 8-9 are not 0000/0200)"},

		// 6to4 2002::/16 carries the IPv4 address in bits 16..47.
		{"2002:7f00:1::", true, "6to4 of 127.0.0.1"},
		{"2002:a9fe:a9fe::1", true, "6to4 of 169.254.169.254"},
		{"2002:808:808::1", false, "6to4 of 8.8.8.8"},

		// Deprecated IPv4-compatible ::/96.
		{"::7f00:1", true, "IPv4-compatible 127.0.0.1"},
		{"::a9fe:a9fe", true, "IPv4-compatible 169.254.169.254"},
		{"::808:808", false, "IPv4-compatible 8.8.8.8"},

		// Representations that already worked must keep working.
		{"::ffff:127.0.0.1", true, "IPv4-mapped loopback"},
		{"203.0.113.7", false, "ordinary public address"},
		{"2001:db8::1", false, "ordinary public IPv6 address"},

		// Zones do not hide a link-local address.
		{"fe80::1%eth0", true, "zoned link-local"},
	} {
		if got := tunDestinationDenied(netip.MustParseAddr(tc.dst)); got != tc.want {
			t.Errorf("tunDestinationDenied(%s) = %v, want %v (%s)", tc.dst, got, tc.want, tc.why)
		}
	}
}

func TestTunDestinationDeniedInvalidAddress(t *testing.T) {
	if !tunDestinationDenied(netip.Addr{}) {
		t.Fatal("the zero netip.Addr must be denied, not treated as an ordinary destination")
	}
}

func TestTunFlowAllowedZeroDestinationWithoutRestrictions(t *testing.T) {
	f := flow("tcp", "203.0.113.7:80")
	f.Dst = netip.AddrPortFrom(netip.Addr{}, 80)
	if tunFlowAllowed(nil, f) {
		t.Fatal("a flow with an invalid destination address was allowed")
	}
}

func TestTunDenyListExtrasCanBeLiftedButEmbeddedFormsCannot(t *testing.T) {
	rules := tunRules(t, `
restrictions:
  - name: metadata-lab
    match:
      - Any
    allow:
      - !Tunnel
        protocol: [Tun]
      - !Tunnel
        protocol: [Tcp]
        cidr: [100.100.100.200/32, 127.0.0.1/32]
`)
	rule := &rules.Restrictions[0]
	for _, tc := range []struct {
		dst  string
		want bool
		why  string
	}{
		{"100.100.100.200:80", true, "an explicit /32 names the Alibaba metadata address"},
		{"168.63.129.16:80", false, "Azure is not named by the rule"},
		{"127.0.0.1:80", true, "an explicit /32 names loopback"},
		{"[64:ff9b::7f00:1]:80", false, "NAT64 of loopback is not matched by an IPv4 rule and cannot be lifted"},
		{"[2002:7f00:1::]:80", false, "6to4 of loopback cannot be lifted"},
	} {
		if got := tunFlowAllowed(rule, flow("tcp", tc.dst)); got != tc.want {
			t.Errorf("tunFlowAllowed(%s) = %v, want %v (%s)", tc.dst, got, tc.want, tc.why)
		}
	}
}
