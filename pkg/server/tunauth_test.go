package server

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/kad/wstunnel-go/pkg/protocol"
	"github.com/kad/wstunnel-go/pkg/tun"
	"go.yaml.in/yaml/v3"
)

// tunRules parses a restrictions document in the Rust YAML schema.
func tunRules(t *testing.T, doc string) *RestrictionsRules {
	t.Helper()
	rules := &RestrictionsRules{}
	if err := yaml.Unmarshal([]byte(doc), rules); err != nil {
		t.Fatalf("parse restrictions: %v", err)
	}
	return rules
}

func flow(network, dst string) tun.Flow {
	return tun.Flow{Network: network, Src: netip.MustParseAddrPort("198.18.0.1:40000"), Dst: netip.MustParseAddrPort(dst)}
}

func TestTunFlowAllowedWithoutRestrictions(t *testing.T) {
	for _, tc := range []struct {
		dst  string
		want bool
	}{
		{"203.0.113.7:443", true},
		{"10.1.2.3:22", true},
		{"[2001:db8::1]:443", true},
		{"127.0.0.1:8080", false},
		{"127.1.2.3:8080", false},
		{"0.0.0.0:80", false},
		{"169.254.169.254:80", false},
		{"224.0.0.251:5353", false},
		{"255.255.255.255:67", false},
		{"[::1]:8080", false},
		{"[::ffff:127.0.0.1]:8080", false},
		{"[fe80::1]:80", false},
		{"[ff02::1]:80", false},
		{"[fd00:ec2::254]:80", false},
	} {
		if got := tunFlowAllowed(nil, flow("tcp", tc.dst)); got != tc.want {
			t.Errorf("tunFlowAllowed(nil, tcp %s) = %v, want %v", tc.dst, got, tc.want)
		}
	}
}

func TestTunFlowAllowedWithRestriction(t *testing.T) {
	rules := tunRules(t, `
restrictions:
  - name: tun
    match:
      - Any
    allow:
      - !Tunnel
        protocol: [Tun]
      - !Tunnel
        protocol: [Tcp]
        port: ["443", "8000..8100"]
        cidr: [10.0.0.0/8, 0.0.0.0/0]
      - !Tunnel
        protocol: [Udp]
        port: ["53"]
        cidr: [10.0.0.53/32]
      - !Tunnel
        protocol: [Tcp]
        cidr: [127.0.0.1/32]
`)
	rule := &rules.Restrictions[0]
	for _, tc := range []struct {
		network, dst string
		want         bool
	}{
		{"tcp", "10.1.2.3:443", true},
		{"tcp", "203.0.113.7:8050", true}, // 0.0.0.0/0 admits public addresses
		{"tcp", "10.1.2.3:22", false},     // port not listed
		{"udp", "10.0.0.53:53", true},
		{"udp", "10.0.0.54:53", false},
		{"udp", "10.1.2.3:443", false},  // Tcp entry does not admit UDP
		{"tcp", "127.0.0.1:9999", true}, // named by an explicit /32
		{"tcp", "127.0.0.2:443", false}, // only 0.0.0.0/0 contains it
		{"tcp", "169.254.169.254:443", false},
	} {
		if got := tunFlowAllowed(rule, flow(tc.network, tc.dst)); got != tc.want {
			t.Errorf("tunFlowAllowed(%s %s) = %v, want %v", tc.network, tc.dst, got, tc.want)
		}
	}
}

func TestTunOnlyRuleAdmitsSessionButNoFlows(t *testing.T) {
	rules := tunRules(t, `
restrictions:
  - name: tun-only
    match:
      - Any
    allow:
      - !Tunnel
        protocol: [Tun]
`)
	claims := &protocol.JwtTunnelConfig{Protocol: protocol.LocalProtocol{Tun: &protocol.TunProtocol{Mtu: 1500}}}
	rule, ok := rules.ValidateMatch(claims, "/v1/events", "", "")
	if !ok || rule == nil {
		t.Fatalf("ValidateMatch = %v, %v; want the tun-only rule", rule, ok)
	}
	if tunFlowAllowed(rule, flow("tcp", "203.0.113.7:443")) {
		t.Fatal("a Tun-only rule admitted a TCP flow")
	}
}

func TestValidateMatchReturnsAdmittingRule(t *testing.T) {
	rules := tunRules(t, `
restrictions:
  - name: tcp-only
    match:
      - Any
    allow:
      - !Tunnel
        protocol: [Tcp]
  - name: tun
    match:
      - Any
    allow:
      - !Tunnel
        protocol: [Tun]
`)
	claims := &protocol.JwtTunnelConfig{Protocol: protocol.LocalProtocol{Tun: &protocol.TunProtocol{}}}
	rule, ok := rules.ValidateMatch(claims, "/", "", "")
	if !ok || rule == nil || rule.Name != "tun" {
		t.Fatalf("ValidateMatch = %+v, %v; want rule \"tun\"", rule, ok)
	}
	if rule, ok := (*RestrictionsRules)(nil).ValidateMatch(claims, "/", "", ""); !ok || rule != nil {
		t.Fatalf("nil rules ValidateMatch = %v, %v; want nil, true", rule, ok)
	}
}

func tunClaim(remote string, port uint16) *protocol.JwtTunnelConfig {
	return &protocol.JwtTunnelConfig{
		ID:       "t",
		Protocol: protocol.LocalProtocol{Tun: &protocol.TunProtocol{Mtu: 1500}},
		Remote:   remote,
		Port:     port,
	}
}

// admitAndAuthorize mimics the handler: normalize the claim, match a rule,
// then authorize one flow against the matched rule.
func admitAndAuthorize(t *testing.T, s *Server, claims *protocol.JwtTunnelConfig, network, dst string) (admitted, flowOK bool) {
	t.Helper()
	normalizeTunClaims(claims)
	rule, ok := s.rules.ValidateMatch(claims, "/v1/events", "", "")
	if !ok {
		return false, false
	}
	return true, tunFlowAllowed(rule, flow(network, dst))
}

func TestRestrictToAdmitsTunSessions(t *testing.T) {
	s := NewServer(Config{EnableTun: true, RestrictTo: []string{"10.0.0.1:22"}})
	for _, tc := range []struct {
		name     string
		claim    *protocol.JwtTunnelConfig
		dst      string
		admitted bool
		flowOK   bool
	}{
		{"honest, allowed flow", tunClaim("0.0.0.0", 0), "10.0.0.1:22", true, true},
		{"honest, other host", tunClaim("0.0.0.0", 0), "10.0.0.2:22", true, false},
		{"honest, other port", tunClaim("0.0.0.0", 0), "10.0.0.1:23", true, false},
		{"forged r/rp behave the same", tunClaim("10.0.0.1", 22), "10.0.0.2:22", true, false},
		{"forged r/rp to elsewhere", tunClaim("192.0.2.9", 9), "10.0.0.1:22", true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			admitted, flowOK := admitAndAuthorize(t, s, tc.claim, "tcp", tc.dst)
			if admitted != tc.admitted || flowOK != tc.flowOK {
				t.Fatalf("admitted=%v flowOK=%v, want %v/%v", admitted, flowOK, tc.admitted, tc.flowOK)
			}
		})
	}
}

func TestTunClaimNotAdmittedByTcpOnlyRule(t *testing.T) {
	s := &Server{rules: tunRules(t, `
restrictions:
  - name: tcp-only
    match: [Any]
    allow:
      - !Tunnel
        protocol: [Tcp]
        cidr: [10.0.0.1/32]
        port: ["22"]
`)}
	for _, c := range []*protocol.JwtTunnelConfig{tunClaim("0.0.0.0", 0), tunClaim("10.0.0.1", 22)} {
		if admitted, _ := admitAndAuthorize(t, s, c, "tcp", "10.0.0.1:22"); admitted {
			t.Fatalf("tun claim r=%s rp=%d admitted by a Tcp-only rule", c.Remote, c.Port)
		}
	}
}

func TestProtocolLessRuleDoesNotDependOnForgedClaim(t *testing.T) {
	// No protocol list: only the (client-controlled) r/rp could satisfy it.
	s := &Server{rules: tunRules(t, `
restrictions:
  - name: host-port-only
    match: [Any]
    allow:
      - !Tunnel
        cidr: [10.0.0.1/32]
        port: ["22"]
`)}
	for _, c := range []*protocol.JwtTunnelConfig{tunClaim("0.0.0.0", 0), tunClaim("10.0.0.1", 22)} {
		if admitted, _ := admitAndAuthorize(t, s, c, "tcp", "10.0.0.1:22"); admitted {
			t.Fatalf("tun claim r=%s rp=%d admitted through forged destination", c.Remote, c.Port)
		}
	}
}

func TestEmptyTunnelRuleAdmitsTunAndAllNonDeniedFlows(t *testing.T) {
	s := &Server{rules: tunRules(t, `
restrictions:
  - name: everything
    match: [Any]
    allow:
      - !Tunnel {}
`)}
	for _, tc := range []struct {
		dst  string
		want bool
	}{
		{"203.0.113.7:443", true},
		{"10.9.9.9:1", true},
		{"[2001:db8::1]:443", true},
		{"127.0.0.1:80", false},
		{"169.254.169.254:80", false},
	} {
		admitted, ok := admitAndAuthorize(t, s, tunClaim("0.0.0.0", 0), "tcp", tc.dst)
		if !admitted || ok != tc.want {
			t.Errorf("%s: admitted=%v flowOK=%v, want admitted and %v", tc.dst, admitted, ok, tc.want)
		}
	}
}

func TestTunDenyListLiftRequiresCIDRInsideDeniedPrefix(t *testing.T) {
	for _, tc := range []struct {
		name string
		cidr string
		dst  string
		want bool
	}{
		{"routing pair low half", "0.0.0.0/1, 128.0.0.0/1", "127.0.0.1:80", false},
		{"routing pair metadata", "0.0.0.0/1, 128.0.0.0/1", "169.254.169.254:80", false},
		{"routing pair unspecified", "0.0.0.0/1, 128.0.0.0/1", "0.0.0.0:80", false},
		{"routing pair multicast", "0.0.0.0/1, 128.0.0.0/1", "224.0.0.1:80", false},
		{"routing pair public", "0.0.0.0/1, 128.0.0.0/1", "203.0.113.7:80", true},
		{"default route v4", "0.0.0.0/0", "127.0.0.1:80", false},
		{"default route v6", "::/0", "[::1]:80", false},
		{"v6 half", "::/1", "[::1]:80", false},
		{"/8 lifts loopback", "127.0.0.0/8", "127.0.0.1:80", true},
		{"/8 lifts other loopback", "127.0.0.0/8", "127.9.9.9:80", true},
		{"/8 does not lift link-local", "127.0.0.0/8", "169.254.169.254:80", false},
		{"/32 lifts that address", "127.0.0.1/32", "127.0.0.1:80", true},
		{"/32 not another address", "127.0.0.1/32", "127.0.0.2:80", false},
		{"/16 link-local lifts metadata", "169.254.0.0/16", "169.254.169.254:80", true},
		{"/15 straddling link-local", "169.254.0.0/15", "169.254.169.254:80", false},
		{"straddle 126.0.0.0/7", "126.0.0.0/7", "127.0.0.1:80", false},
		{"v6 loopback /128", "::1/128", "[::1]:80", true},
		{"v6 loopback not link-local", "::1/128", "[fe80::1]:80", false},
		{"mapped destination", "127.0.0.1/32", "[::ffff:127.0.0.1]:80", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rule := &tunRules(t, "restrictions:\n  - name: r\n    match: [Any]\n    allow:\n      - !Tunnel\n        protocol: [Tcp]\n        cidr: [\""+strings.ReplaceAll(tc.cidr, ", ", "\", \"")+"\"]\n").Restrictions[0]
			if got := tunFlowAllowed(rule, flow("tcp", tc.dst)); got != tc.want {
				t.Fatalf("cidr %s, dst %s: allowed = %v, want %v", tc.cidr, tc.dst, got, tc.want)
			}
		})
	}
}
