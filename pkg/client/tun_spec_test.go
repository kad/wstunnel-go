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

func TestParseTunnelArgRejectsTun(t *testing.T) {
	for _, reverse := range []bool{false, true} {
		if _, err := ParseTunnelArg("tun://wst0", reverse); err == nil || !strings.Contains(err.Error(), "ParseTunArg") {
			t.Errorf("ParseTunnelArg(tun, reverse=%v) error = %v, want a pointer to ParseTunArg", reverse, err)
		}
	}
}
