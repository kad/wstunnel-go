package server

import (
	"net/netip"
	"reflect"
	"strings"
	"testing"
)

func TestParseTunAllow(t *testing.T) {
	got, err := ParseTunAllow([]string{"10.0.0.0/8", "192.0.2.77/24", "203.0.113.9", "2001:db8::/32", "2001:db8::1", "::ffff:198.51.100.0/120"})
	if err != nil {
		t.Fatal(err)
	}
	want := []netip.Prefix{
		netip.MustParsePrefix("10.0.0.0/8"),
		netip.MustParsePrefix("192.0.2.0/24"), // masked
		netip.MustParsePrefix("203.0.113.9/32"),
		netip.MustParsePrefix("2001:db8::/32"),
		netip.MustParsePrefix("2001:db8::1/128"),
		netip.MustParsePrefix("198.51.100.0/24"), // 4in6 converted
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("ParseTunAllow = %v, want %v", got, want)
	}
	if none, err := ParseTunAllow(nil); err != nil || len(none) != 0 {
		t.Fatalf("ParseTunAllow(nil) = %v, %v; want nothing", none, err)
	}
	for _, bad := range []string{"", "not-an-address", "10.0.0.0/33", "10.0.0.0/", "300.1.1.1", "::ffff:10.0.0.0/8"} {
		if _, err := ParseTunAllow([]string{"10.0.0.0/8", bad}); err == nil || !strings.Contains(err.Error(), "tun_allow") {
			t.Errorf("ParseTunAllow(%q) error = %v, want one naming tun_allow", bad, err)
		}
	}
}

func TestAuthorizeTunFlowTunAllow(t *testing.T) {
	s := NewServer(Config{TunAllow: []string{"10.0.0.0/8", "203.0.113.9"}})
	for _, tc := range []struct {
		dst  string
		want bool
		why  string
	}{
		{"10.1.2.3:443", true, "inside a listed network"},
		{"[::ffff:10.1.2.3]:443", true, "IPv4-mapped form of a listed address"},
		{"203.0.113.9:22", true, "the single listed host"},
		{"203.0.113.10:22", false, "next address is not listed"},
		{"11.0.0.1:443", false, "outside every listed network"},
		{"[2001:db8::1]:443", false, "IPv6 is not listed"},
	} {
		if got := s.authorizeTunFlow(nil, flow("tcp", tc.dst)); got != tc.want {
			t.Errorf("authorizeTunFlow(%s) = %v, want %v (%s)", tc.dst, got, tc.want, tc.why)
		}
	}
}

func TestTunAllowDoesNotLiftTheDenyList(t *testing.T) {
	s := NewServer(Config{TunAllow: []string{"127.0.0.0/8"}})
	if s.authorizeTunFlow(nil, flow("tcp", "127.0.0.1:80")) {
		t.Fatal("tun_allow alone allowed loopback; the deny list must still apply")
	}
	rules := tunRules(t, `
restrictions:
  - name: lab
    match:
      - Any
    allow:
      - !Tunnel
        protocol: [Tun]
      - !Tunnel
        protocol: [Tcp]
        cidr: [127.0.0.1/32]
`)
	if !s.authorizeTunFlow(&rules.Restrictions[0], flow("tcp", "127.0.0.1:80")) {
		t.Fatal("a rule naming 127.0.0.1/32 plus tun_allow covering it should allow loopback")
	}
	if s.authorizeTunFlow(&rules.Restrictions[0], flow("tcp", "10.0.0.1:80")) {
		t.Fatal("a destination outside tun_allow was allowed because the rule had no CIDR for it")
	}
}

func TestInvalidTunAllowDeniesEveryTunFlow(t *testing.T) {
	s := NewServer(Config{TunAllow: []string{"10.0.0.0/8", "bogus"}})
	for _, dst := range []string{"10.1.2.3:80", "203.0.113.7:80", "[2001:db8::1]:80"} {
		if s.authorizeTunFlow(nil, flow("tcp", dst)) {
			t.Errorf("flow to %s was allowed although tun_allow failed to parse; it must fail closed", dst)
		}
	}
}

func TestNoTunAllowMeansNoExtraLimit(t *testing.T) {
	s := NewServer(Config{})
	if !s.authorizeTunFlow(nil, flow("tcp", "203.0.113.7:80")) {
		t.Fatal("without tun_allow an ordinary public destination must be allowed")
	}
}
