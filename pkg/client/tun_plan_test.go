package client

import (
	"errors"
	"fmt"
	"net/netip"
	"reflect"
	"strings"
	"testing"
)

type recordingConfigurer struct {
	calls   []string
	failOn  string // exact call text that returns an error
	failErr error
}

func (r *recordingConfigurer) record(call string) error {
	r.calls = append(r.calls, call)
	if call == r.failOn {
		return r.failErr
	}
	return nil
}

func (r *recordingConfigurer) SetMTU(ifname string, mtu int) error {
	return r.record(fmt.Sprintf("mtu %s %d", ifname, mtu))
}
func (r *recordingConfigurer) AddAddr(ifname string, p netip.Prefix) error {
	return r.record(fmt.Sprintf("addr %s %s", ifname, p))
}
func (r *recordingConfigurer) LinkUp(ifname string) error { return r.record("up " + ifname) }
func (r *recordingConfigurer) AddRoute(ifname string, dst netip.Prefix) error {
	return r.record(fmt.Sprintf("route %s %s", ifname, dst))
}

func mustSpec(t *testing.T, arg string) *TunSpec {
	t.Helper()
	spec, err := ParseTunArg(arg)
	if err != nil {
		t.Fatalf("ParseTunArg(%q): %v", arg, err)
	}
	return spec
}

func TestPlanTunNetConfigOrder(t *testing.T) {
	spec := mustSpec(t, "tun://wst0?mtu=1400&addr=10.9.0.2/32&route=10.0.0.0/8&route=172.16.0.0/12")
	ops, err := planTunNetConfig(spec, []netip.Addr{netip.MustParseAddr("203.0.113.5")})
	if err != nil {
		t.Fatal(err)
	}
	rec := &recordingConfigurer{}
	if err := applyNetOps("wst0", ops, rec); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"mtu wst0 1400",
		"addr wst0 10.9.0.2/32",
		"up wst0",
		"route wst0 10.0.0.0/8",
		"route wst0 172.16.0.0/12",
	}
	if !reflect.DeepEqual(rec.calls, want) {
		t.Fatalf("calls = %v, want %v (routes need the link up, so they come last)", rec.calls, want)
	}
}

func TestPlanTunNetConfigAttachOnlyPlansNothing(t *testing.T) {
	ops, err := planTunNetConfig(mustSpec(t, "tun://wst0?configure=false"), nil)
	if err != nil || len(ops) != 0 {
		t.Fatalf("plan = %v, %v; want no steps", ops, err)
	}
}

func TestPlanTunNetConfigLoopGuard(t *testing.T) {
	server := netip.MustParseAddr("203.0.113.5")
	for _, tc := range []struct {
		route   string
		wantErr bool
	}{
		{"203.0.113.0/24", true},
		{"203.0.113.5/32", true},
		{"0.0.0.0/0", true},
		{"128.0.0.0/1", true}, // 203.x has its top bit set: the upper half
		{"0.0.0.0/1", false},
		{"10.0.0.0/8", false},
		{"203.0.114.0/24", false},
	} {
		spec := mustSpec(t, "tun://wst0?route="+tc.route)
		_, err := planTunNetConfig(spec, []netip.Addr{server})
		if gotErr := err != nil; gotErr != tc.wantErr {
			t.Errorf("route %s: error = %v, want error %v", tc.route, err, tc.wantErr)
		}
		if err != nil && !strings.Contains(err.Error(), "loop") {
			t.Errorf("route %s: error %q should explain the loop", tc.route, err)
		}
	}
}

func TestPlanTunNetConfigLoopGuardMappedAndV6(t *testing.T) {
	spec := mustSpec(t, "tun://wst0?route=2001:db8::/32&route=198.51.100.0/24")
	if _, err := planTunNetConfig(spec, []netip.Addr{netip.MustParseAddr("::ffff:198.51.100.7")}); err == nil {
		t.Error("an IPv4-mapped server address inside an IPv4 route must trip the guard")
	}
	if _, err := planTunNetConfig(spec, []netip.Addr{netip.MustParseAddr("2001:db8::1")}); err == nil {
		t.Error("an IPv6 server address inside an IPv6 route must trip the guard")
	}
	if _, err := planTunNetConfig(spec, []netip.Addr{netip.MustParseAddr("2001:db9::1")}); err != nil {
		t.Errorf("unrelated IPv6 server address tripped the guard: %v", err)
	}
}

func TestApplyNetOpsStopsAtFirstRequiredFailure(t *testing.T) {
	spec := mustSpec(t, "tun://wst0?addr=10.9.0.2/32&route=10.0.0.0/8")
	ops, _ := planTunNetConfig(spec, []netip.Addr{netip.MustParseAddr("203.0.113.5")})
	boom := errors.New("boom")
	rec := &recordingConfigurer{failOn: "addr wst0 10.9.0.2/32", failErr: boom}
	err := applyNetOps("wst0", ops, rec)
	if !errors.Is(err, boom) || !strings.Contains(err.Error(), "add address 10.9.0.2/32") {
		t.Fatalf("error = %v, want boom naming the failed step", err)
	}
	for _, call := range rec.calls {
		if strings.HasPrefix(call, "route") || strings.HasPrefix(call, "up") {
			t.Fatalf("steps after the failure ran: %v", rec.calls)
		}
	}
}

func TestApplyNetOpsSkipsOptionalDefaultIPv6(t *testing.T) {
	spec := mustSpec(t, "tun://wst0?route=10.0.0.0/8") // default addresses: v4 required, v6 optional
	ops, _ := planTunNetConfig(spec, []netip.Addr{netip.MustParseAddr("203.0.113.5")})
	rec := &recordingConfigurer{failOn: "addr wst0 fd77:7473::1/128", failErr: errors.New("ipv6 disabled")}
	if err := applyNetOps("wst0", ops, rec); err != nil {
		t.Fatalf("a failing default IPv6 address must not abort startup: %v", err)
	}
	if rec.calls[len(rec.calls)-1] != "route wst0 10.0.0.0/8" {
		t.Fatalf("configuration did not continue past the optional step: %v", rec.calls)
	}
}

func TestApplyNetOpsOperatorIPv6IsRequired(t *testing.T) {
	spec := mustSpec(t, "tun://wst0?addr=fd00::2/128")
	ops, _ := planTunNetConfig(spec, []netip.Addr{netip.MustParseAddr("203.0.113.5")})
	rec := &recordingConfigurer{failOn: "addr wst0 fd00::2/128", failErr: errors.New("ipv6 disabled")}
	if err := applyNetOps("wst0", ops, rec); err == nil {
		t.Fatal("an IPv6 address the operator asked for must be required")
	}
}

func TestPlanTunNetConfigFailsClosedWithoutServerAddress(t *testing.T) {
	spec := mustSpec(t, "tun://wst0?route=10.0.0.0/8")
	for _, addrs := range [][]netip.Addr{nil, {}} {
		if _, err := planTunNetConfig(spec, addrs); err == nil {
			t.Errorf("routes with server addresses %#v must be refused", addrs)
		}
	}
	if _, err := planTunNetConfig(mustSpec(t, "tun://wst0"), []netip.Addr{}); err != nil {
		t.Errorf("no routes needs no server address: %v", err)
	}
	if _, err := planTunNetConfig(mustSpec(t, "tun://wst0?configure=false"), []netip.Addr{}); err != nil {
		t.Errorf("configure=false needs no server address: %v", err)
	}
}
