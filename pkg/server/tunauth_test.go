package server

import (
	"net/netip"
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
