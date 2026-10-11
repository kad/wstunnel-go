package client

import (
	"errors"
	"fmt"
	"net/netip"
	"reflect"
	"slices"
	"strings"
	"sync"
	"syscall"
	"testing"
)

type recordingConfigurer struct {
	mu      sync.Mutex
	calls   []string
	failOn  string // exact call text that returns an error
	failErr error
	routes  routeGetter // answers RouteGet

	existingRules []ruleSpec // returned by ListRules
}

func (r *recordingConfigurer) record(call string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
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

// The full-tunnel operations are recorded as the call text, and a tiny state
// model checks that undo is symmetric.
func (r *recordingConfigurer) DelRoute(ifname string, dst netip.Prefix) error {
	return r.record(fmt.Sprintf("delroute %s %s", ifname, dst))
}
func (r *recordingConfigurer) AddTableRoute(ifname string, dst netip.Prefix, table int) error {
	return r.record(fmt.Sprintf("tableroute %s %s table %d", ifname, dst, table))
}
func (r *recordingConfigurer) DelTableRoute(ifname string, dst netip.Prefix, table int) error {
	return r.record(fmt.Sprintf("deltableroute %s %s table %d", ifname, dst, table))
}
func (r *recordingConfigurer) AddHostRoute(dst netip.Prefix, gw netip.Addr, link string) error {
	return r.record(fmt.Sprintf("hostroute %s via %s dev %s", dst, gw, link))
}
func (r *recordingConfigurer) DelHostRoute(dst netip.Prefix, gw netip.Addr, link string) error {
	return r.record(fmt.Sprintf("delhostroute %s via %s dev %s", dst, gw, link))
}
func (r *recordingConfigurer) AddRule(rule ruleSpec) error {
	if err := r.record("rule add " + rule.String()); err != nil {
		return err
	}
	r.mu.Lock()
	r.existingRules = append(r.existingRules, rule)
	r.mu.Unlock()
	return nil
}

// DelRule behaves like the kernel: it removes one matching rule, or says there
// is none (ENOENT).
func (r *recordingConfigurer) DelRule(rule ruleSpec) error {
	if err := r.record("rule del " + rule.String()); err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	for i, have := range r.existingRules {
		if have == rule {
			r.existingRules = slices.Delete(r.existingRules, i, i+1)
			return nil
		}
	}
	return syscall.ENOENT
}

func (r *recordingConfigurer) snapshot() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return slices.Clone(r.calls)
}
func (r *recordingConfigurer) ListRules(family int) ([]ruleSpec, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, fmt.Sprintf("listrules %d", family))
	var out []ruleSpec
	for _, rule := range r.existingRules {
		if rule.Family == family {
			out = append(out, rule)
		}
	}
	return out, nil
}
func (r *recordingConfigurer) RouteGet(ip netip.Addr, avoid string) (routeInfo, error) {
	r.mu.Lock()
	r.calls = append(r.calls, fmt.Sprintf("routeget %s avoid %s", ip, avoid))
	r.mu.Unlock()
	if r.routes == nil {
		return routeInfo{}, errors.New("no route")
	}
	return r.routes.RouteGet(ip)
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
		{"203.0.112.0/23", true},
		{"203.0.0.0/8", true},
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

func TestPlanTunNetConfigLoopGuardCoversConnectedRoutes(t *testing.T) {
	v4 := []netip.Addr{netip.MustParseAddr("203.0.113.5")}
	// A shorter-than-host prefix on the device installs a route for the whole
	// network into it.
	_, err := planTunNetConfig(mustSpec(t, "tun://wst0?addr=203.0.113.1/24"), v4)
	if err == nil || !strings.Contains(err.Error(), "loop") || !strings.Contains(err.Error(), "connected route") {
		t.Errorf("addr 203.0.113.1/24 with server 203.0.113.5: error = %v, want a loop error naming the connected route", err)
	}
	if _, err := planTunNetConfig(mustSpec(t, "tun://wst0?addr=203.0.113.1/32"), v4); err != nil {
		t.Errorf("a host address creates no connected route: %v", err)
	}
	v6 := []netip.Addr{netip.MustParseAddr("fd00::77")}
	if _, err := planTunNetConfig(mustSpec(t, "tun://wst0?addr=fd00::1/64"), v6); err == nil {
		t.Error("addr fd00::1/64 with a server inside fd00::/64 must be refused")
	}
	if _, err := planTunNetConfig(mustSpec(t, "tun://wst0?addr=fd00::1/128"), v6); err != nil {
		t.Errorf("an IPv6 host address creates no connected route: %v", err)
	}
}

func TestPlanTunNetConfigLoopGuardNormalisesAddresses(t *testing.T) {
	server := []netip.Addr{netip.MustParseAddr("203.0.113.5")}
	// A 4in6 prefix is the IPv4 network it names.
	spec := &TunSpec{Configure: true, MTU: 1500, Routes: []netip.Prefix{netip.MustParsePrefix("::ffff:203.0.113.0/120")}}
	if _, err := planTunNetConfig(spec, server); err == nil {
		t.Error("a 4in6 route prefix covering an IPv4 server must be refused")
	}
	// netip.Prefix.Contains is false for a zoned address.
	spec = &TunSpec{Configure: true, MTU: 1500, Routes: []netip.Prefix{netip.MustParsePrefix("fe80::/10")}}
	if _, err := planTunNetConfig(spec, []netip.Addr{netip.MustParseAddr("fe80::1%eth0")}); err == nil {
		t.Error("a zoned server address inside the route must be refused")
	}
}

func TestPlanTunNetConfigRejectsWholeHostRoutes(t *testing.T) {
	v4 := []netip.Addr{netip.MustParseAddr("203.0.113.5")}
	v6 := []netip.Addr{netip.MustParseAddr("2001:db8::1")}
	for _, tc := range []struct {
		route   string
		servers []netip.Addr
	}{
		{"::/0", v4},      // the server is in the other family: the loop guard cannot see it
		{"0.0.0.0/0", v6}, // likewise
		{"0.0.0.0/0", v4},
		{"0.0.0.0/1", v4},
		{"128.0.0.0/1", v6},
		{"::/1", v4},
		{"8000::/1", v4},
	} {
		_, err := planTunNetConfig(mustSpec(t, "tun://wst0?route="+tc.route), tc.servers)
		if err == nil || !strings.Contains(err.Error(), "would capture all") || !strings.Contains(err.Error(), "route=default") {
			t.Errorf("route %s: error = %v, want a whole-host routing refusal", tc.route, err)
		}
	}
	for _, route := range []string{"0.0.0.0/2", "10.0.0.0/8", "8.0.0.0/5", "fd00::/8", "::/2"} {
		if _, err := planTunNetConfig(mustSpec(t, "tun://wst0?route="+route), v4); err != nil {
			t.Errorf("route %s must stay accepted: %v", route, err)
		}
	}
	// Only configured devices get routes; configure=false is untouched.
	if _, err := planTunNetConfig(mustSpec(t, "tun://wst0?configure=false"), v4); err != nil {
		t.Error(err)
	}
}

func TestCheckNotWholeHostComparesMaskedPrefix(t *testing.T) {
	// Hand-built specs are not masked by the parser.
	for _, route := range []string{"200.0.0.1/1", "1.2.3.4/0", "7f00::1/1", "::1/0", "0.0.0.0/1", "128.0.0.0/1"} {
		spec := &TunSpec{Configure: true, Routes: []netip.Prefix{netip.MustParsePrefix(route)}}
		if err := checkTunLoops(spec, []netip.Addr{netip.MustParseAddr("203.0.113.5")}); err == nil || !strings.Contains(err.Error(), "capture all") {
			t.Errorf("route %s = %v, want a whole-host refusal", route, err)
		}
	}
	spec := &TunSpec{Configure: true, Routes: []netip.Prefix{netip.MustParsePrefix("64.0.0.1/2")}}
	if err := checkTunLoops(spec, []netip.Addr{netip.MustParseAddr("203.0.113.5")}); err != nil {
		t.Errorf("a /2 is not the whole host: %v", err)
	}
}

func TestPlannerRefusesAddrWithZeroLength(t *testing.T) {
	spec := &TunSpec{Configure: true, MTU: 1500, Addrs: []netip.Prefix{netip.MustParsePrefix("10.0.0.1/0")}}
	if _, err := planTunNetConfig(spec, []netip.Addr{netip.MustParseAddr("203.0.113.5")}); err == nil || !strings.Contains(err.Error(), "loop") {
		t.Fatalf("addr /0 = %v, want a loop refusal", err)
	}
}

func TestWholeHostRefusalPointsAtRouteDefault(t *testing.T) {
	spec := &TunSpec{Configure: true, Routes: []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")}}
	err := checkTunLoops(spec, []netip.Addr{netip.MustParseAddr("203.0.113.5")})
	if err == nil || !strings.Contains(err.Error(), "route=default") {
		t.Fatalf("error = %v, want a pointer to route=default", err)
	}
}

func TestFullTunnelSpecSkipsRouteLoopGuardButKeepsAddrCheck(t *testing.T) {
	servers := []netip.Addr{netip.MustParseAddr("203.0.113.5")}
	spec := mustSpec(t, "tun://wst0?route=default")
	if err := checkTunLoops(spec, servers); err != nil {
		t.Fatalf("full tunnel: %v", err)
	}
	// A connected route to the server's own network would still capture its traffic.
	spec = mustSpec(t, "tun://wst0?route=default&addr=203.0.113.9/24")
	if err := checkTunLoops(spec, servers); err == nil || !strings.Contains(err.Error(), "loop") {
		t.Fatalf("addr covering the server = %v, want a loop error", err)
	}
}
