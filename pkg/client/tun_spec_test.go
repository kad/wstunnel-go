package client

import (
	"net/netip"
	"reflect"
	"strings"
	"testing"
)

func mustPrefixes(t *testing.T, ss ...string) []netip.Prefix {
	t.Helper()
	var out []netip.Prefix
	for _, s := range ss {
		out = append(out, netip.MustParsePrefix(s))
	}
	return out
}

func TestIsTunArg(t *testing.T) {
	for arg, want := range map[string]bool{
		"tun://":              true,
		"tun://wst0?mtu=1400": true,
		"tcp://1212:h:80":     false,
		"stun://x":            false,
		"":                    false,
	} {
		if got := IsTunArg(arg); got != want {
			t.Errorf("IsTunArg(%q) = %v, want %v", arg, got, want)
		}
	}
}

func TestParseTunArgDefaults(t *testing.T) {
	spec, err := ParseTunArg("tun://")
	if err != nil {
		t.Fatal(err)
	}
	want := &TunSpec{
		Name:         "",
		MTU:          1500,
		Addrs:        mustPrefixes(t, "198.18.0.1/32", "fd77:7473::1/128"),
		DefaultAddrs: true,
		Configure:    true,
	}
	if !reflect.DeepEqual(spec, want) {
		t.Fatalf("ParseTunArg(\"tun://\") = %+v, want %+v", spec, want)
	}
}

func TestParseTunArgFull(t *testing.T) {
	spec, err := ParseTunArg("tun://wst0?mtu=1400&addr=10.9.0.2/32&addr=fd00::2/128&route=10.0.0.0/8&route=192.168.1.7/24&route=fd00:1::/64")
	if err != nil {
		t.Fatal(err)
	}
	want := &TunSpec{
		Name:      "wst0",
		MTU:       1400,
		Addrs:     mustPrefixes(t, "10.9.0.2/32", "fd00::2/128"),
		Routes:    mustPrefixes(t, "10.0.0.0/8", "192.168.1.0/24", "fd00:1::/64"), // masked
		Configure: true,
	}
	if !reflect.DeepEqual(spec, want) {
		t.Fatalf("spec = %+v, want %+v", spec, want)
	}
}

func TestParseTunArgAttachExisting(t *testing.T) {
	spec, err := ParseTunArg("tun://wst0?configure=false")
	if err != nil {
		t.Fatal(err)
	}
	if spec.Configure || spec.Name != "wst0" || len(spec.Addrs) != 0 || spec.DefaultAddrs {
		t.Fatalf("spec = %+v, want an attach-only spec without default addresses", spec)
	}
}

func TestParseTunArgErrors(t *testing.T) {
	for arg, wantSubstr := range map[string]string{
		"tcp://wst0":                                  "not a tun:// tunnel",
		"tun://wst0?mtu=1279":                         "invalid tun:// mtu",
		"tun://wst0?mtu=65536":                        "invalid tun:// mtu",
		"tun://wst0?mtu=abc":                          "invalid tun:// mtu",
		"tun://wst0?addr=not-a-prefix":                "invalid tun:// addr",
		"tun://wst0?addr=10.0.0.1":                    "invalid tun:// addr", // prefix length required
		"tun://wst0?route=10.0.0.0/33":                "invalid tun:// route",
		"tun://wst0?configure=maybe":                  "invalid tun:// configure",
		"tun://wst0?bogus=1":                          "unknown tun:// option",
		"tun://averyveryverylongname0":                "longer than 15",
		"tun://a/b":                                   "invalid tun:// device name",
		"tun://-wst0":                                 "must not start with '-'",
		"tun://--help":                                "must not start with '-'",
		"tun://wst0?configure=false&addr=10.0.0.1/32": "no effect with configure=false",
		"tun://wst0?configure=false&route=10.0.0.0/8": "no effect with configure=false",
		"tun://?configure=false":                      "needs the name of an existing device",
	} {
		_, err := ParseTunArg(arg)
		if err == nil || !strings.Contains(err.Error(), wantSubstr) {
			t.Errorf("ParseTunArg(%q) error = %v, want substring %q", arg, err, wantSubstr)
		}
	}
}

func TestParseTunArgStrictness(t *testing.T) {
	for arg, wantSubstr := range map[string]string{
		"tun://wst0?mtu=":                       "empty",
		"tun://wst0?configure=":                 "empty",
		"tun://wst0?mtu=1400&mtu=1500":          "more than once",
		"tun://wst0?configure=true&configure=1": "more than once",
		"tun://wst0\x01":                        "control character",
		"tun://ws\x7ft0":                        "control character",
		"tun://wst\x000":                        "control character",
		"tun://wst0?addr=::ffff:10.0.0.1/128":   "IPv4-mapped",
		"tun://wst0?route=::ffff:10.0.0.0/104":  "IPv4-mapped",
		"tun://wst0?addr=10.0.0.1/0":            "/0",
		"tun://wst0?addr=::1/0":                 "/0",
		"tun://wst0?mtu=1400;addr=10.0.0.1/32":  "invalid tun:// options",
		"tun://wst0?mtu=%zz":                    "invalid tun:// options",
		"tun://wst0?addr=10.0.0.1%2/32":         "invalid tun:// options",
	} {
		_, err := ParseTunArg(arg)
		if err == nil || !strings.Contains(err.Error(), wantSubstr) {
			t.Errorf("ParseTunArg(%q) error = %v, want substring %q", arg, err, wantSubstr)
		}
	}
	// A percent-escaped option is still accepted.
	if _, err := ParseTunArg("tun://wst0?addr=10.0.0.1%2F32"); err != nil {
		t.Errorf("percent-escaped slash rejected: %v", err)
	}
}

func TestIsTunArgIsCaseSensitive(t *testing.T) {
	// Like the other tunnel schemes, the scheme must be lower case.
	for _, arg := range []string{"TUN://wst0", "Tun://wst0"} {
		if IsTunArg(arg) {
			t.Errorf("IsTunArg(%q) = true; the scheme match is case-sensitive", arg)
		}
	}
}

func TestParseTunnelArgRejectsTun(t *testing.T) {
	for _, reverse := range []bool{false, true} {
		if _, err := ParseTunnelArg("tun://wst0", reverse); err == nil || !strings.Contains(err.Error(), "-L 'tun://") || strings.Contains(err.Error(), "ParseTunArg") {
			t.Errorf("ParseTunnelArg(tun, reverse=%v) error = %v, want the user-facing -L 'tun://...' form and no internal function name", reverse, err)
		}
	}
}

func TestParseTunArgFullTunnel(t *testing.T) {
	spec, err := ParseTunArg("tun://wst0?route=default")
	if err != nil {
		t.Fatal(err)
	}
	if !spec.FullTunnel || spec.Routing != "auto" || len(spec.Routes) != 0 || len(spec.DNS) != 0 {
		t.Fatalf("spec = %+v, want FullTunnel, Routing auto, no routes, no dns", spec)
	}
	if !spec.Configure || !spec.DefaultAddrs {
		t.Fatalf("spec = %+v, want the default addresses configured", spec)
	}

	spec, err = ParseTunArg("tun://wst0?route=default&routing=pin&dns=1.1.1.1&dns=2606:4700:4700::1111&dns=1.1.1.1&addr=10.9.0.2/32")
	if err != nil {
		t.Fatal(err)
	}
	if spec.Routing != "pin" {
		t.Errorf("Routing = %q, want pin", spec.Routing)
	}
	wantDNS := []netip.Addr{netip.MustParseAddr("1.1.1.1"), netip.MustParseAddr("2606:4700:4700::1111")}
	if !reflect.DeepEqual(spec.DNS, wantDNS) {
		t.Errorf("DNS = %v, want %v (duplicates dropped)", spec.DNS, wantDNS)
	}

	for _, r := range []string{"auto", "fwmark", "pin"} {
		spec, err := ParseTunArg("tun://wst0?route=default&routing=" + r)
		if err != nil || spec.Routing != r {
			t.Errorf("routing=%s: %+v, %v", r, spec, err)
		}
	}

	// Split-tunnel specs are unchanged.
	spec, err = ParseTunArg("tun://wst0?route=10.0.0.0/8")
	if err != nil || spec.FullTunnel || spec.Routing != "" {
		t.Fatalf("split spec = %+v, %v", spec, err)
	}
}

func TestParseTunArgFullTunnelErrors(t *testing.T) {
	for arg, wantSubstr := range map[string]string{
		"tun://wst0?route=default&route=10.0.0.0/8":         "cannot be combined",
		"tun://wst0?route=10.0.0.0/8&route=default":         "cannot be combined",
		"tun://wst0?route=default&route=default":            "cannot be combined",
		"tun://wst0?route=default&configure=false":          "configure=false",
		"tun://wst0?routing=pin":                            "only valid with route=default",
		"tun://wst0?route=10.0.0.0/8&routing=pin":           "only valid with route=default",
		"tun://wst0?route=default&routing=bogus":            "invalid tun:// routing",
		"tun://wst0?route=default&routing=":                 "empty",
		"tun://wst0?route=default&routing=pin&routing=auto": "more than once",
		"tun://wst0?route=default&routing=PIN":              "invalid tun:// routing",
		"tun://wst0?dns=1.1.1.1":                            "only valid with route=default",
		"tun://wst0?route=10.0.0.0/8&dns=1.1.1.1":           "only valid with route=default",
		"tun://wst0?configure=false&dns=1.1.1.1":            "configure=false",
		"tun://wst0?route=default&dns=one.one.one.one":      "invalid tun:// dns",
		"tun://wst0?route=default&dns=":                     "invalid tun:// dns",
		"tun://wst0?route=default&dns=fe80::1%25eth0":       "zone",
		"tun://wst0?route=default&dns=::ffff:1.1.1.1":       "invalid tun:// dns",
		"tun://wst0?route=default&dns=0.0.0.0":              "invalid tun:// dns",
		"tun://wst0?bogus=1":                                "routing, dns",
	} {
		_, err := ParseTunArg(arg)
		if err == nil || !strings.Contains(err.Error(), wantSubstr) {
			t.Errorf("ParseTunArg(%q) error = %v, want substring %q", arg, err, wantSubstr)
		}
	}
}
