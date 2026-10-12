package client

import (
	"errors"
	"fmt"
	"net/netip"
	"reflect"
	"strings"
	"syscall"
	"testing"
)

func describeAll(ops []netOp) []string {
	var out []string
	for _, op := range ops {
		out = append(out, op.describe())
	}
	return out
}

func routes(table map[string]routeInfo) routeGetter {
	return routeGetFunc(func(ip netip.Addr) (routeInfo, error) {
		if info, ok := table[ip.String()]; ok {
			return info, nil
		}
		return routeInfo{}, fmt.Errorf("no route to %s", ip)
	})
}

var (
	srv4     = netip.MustParseAddr("192.0.2.10")
	srv4b    = netip.MustParseAddr("192.0.2.11")
	srv6     = netip.MustParseAddr("2001:db8::10")
	viaGW    = routeInfo{Gateway: netip.MustParseAddr("10.200.0.2"), Link: "eth0", Src: netip.MustParseAddr("10.200.0.1")}
	onLink   = routeInfo{Link: "eth1"}
	via6     = routeInfo{Gateway: netip.MustParseAddr("fe80::1"), Link: "eth0"}
	allPlans = routes(map[string]routeInfo{"192.0.2.10": viaGW, "192.0.2.11": onLink, "2001:db8::10": via6})
)

func TestPlanFullTunnelFwmark(t *testing.T) {
	ops, undo, err := planFullTunnel(routingConfig{Mode: "fwmark", Mark: 0x7774, Tun: "wst0"}, []netip.Addr{srv4}, nil)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"add route 0.0.0.0/0 dev wst0 table 30580",
		"add route ::/0 dev wst0 table 30580",
		"add rule ipv4 pref 32760 table 254 suppress_prefixlength 0",
		"add rule ipv4 pref 32761 not fwmark 0x7774 table 30580",
		"add rule ipv6 pref 32760 table 254 suppress_prefixlength 0",
		"add rule ipv6 pref 32761 not fwmark 0x7774 table 30580",
	}
	if got := describeAll(ops); !reflect.DeepEqual(got, want) {
		t.Fatalf("ops =\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	wantUndo := []string{
		"delete rule ipv6 pref 32761 not fwmark 0x7774 table 30580",
		"delete rule ipv6 pref 32760 table 254 suppress_prefixlength 0",
		"delete rule ipv4 pref 32761 not fwmark 0x7774 table 30580",
		"delete rule ipv4 pref 32760 table 254 suppress_prefixlength 0",
		"delete route ::/0 dev wst0 table 30580",
		"delete route 0.0.0.0/0 dev wst0 table 30580",
	}
	if got := describeAll(undo); !reflect.DeepEqual(got, wantUndo) {
		t.Fatalf("undo =\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(wantUndo, "\n"))
	}
}

func TestPlanFullTunnelFwmarkUsesGivenMark(t *testing.T) {
	ops, _, err := planFullTunnel(routingConfig{Mode: "fwmark", Mark: 99, Tun: "wst0"}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := describeAll(ops); !strings.Contains(got[0], "table 99") || !strings.Contains(got[3], "fwmark 0x63 table 99") {
		t.Fatalf("ops = %v, want mark and table 99", got)
	}
	for _, mark := range []uint32{0, 253, 254, 255} {
		if _, _, err := planFullTunnel(routingConfig{Mode: "fwmark", Mark: mark, Tun: "wst0"}, nil, nil); err == nil {
			t.Errorf("mark %d accepted; it is a reserved table id", mark)
		}
	}
}

func TestTunMark(t *testing.T) {
	if tunMark(0) != 0x7774 || tunMark(5) != 5 {
		t.Fatalf("tunMark(0) = %#x, tunMark(5) = %d", tunMark(0), tunMark(5))
	}
}

func TestPlanFullTunnelPin(t *testing.T) {
	ops, undo, err := planFullTunnel(routingConfig{Mode: "pin", Tun: "wst0"}, []netip.Addr{srv4, srv4b, srv6}, allPlans)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"add route 192.0.2.10/32 via 10.200.0.2 dev eth0",
		"add route 192.0.2.11/32 dev eth1", // on-link: no gateway
		"add route 2001:db8::10/128 via fe80::1 dev eth0",
		"add route 0.0.0.0/1 dev wst0",
		"add route 128.0.0.0/1 dev wst0",
		"add route ::/1 dev wst0",
		"add route 8000::/1 dev wst0",
	}
	if got := describeAll(ops); !reflect.DeepEqual(got, want) {
		t.Fatalf("ops =\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	// The pins come before the halves, so the server's traffic never has a
	// moment where it is captured.
	wantUndo := []string{
		"delete route 8000::/1 dev wst0",
		"delete route ::/1 dev wst0",
		"delete route 128.0.0.0/1 dev wst0",
		"delete route 0.0.0.0/1 dev wst0",
		"delete route 2001:db8::10/128 via fe80::1 dev eth0",
		"delete route 192.0.2.11/32 dev eth1",
		"delete route 192.0.2.10/32 via 10.200.0.2 dev eth0",
	}
	if got := describeAll(undo); !reflect.DeepEqual(got, wantUndo) {
		t.Fatalf("undo =\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(wantUndo, "\n"))
	}
}

func TestPlanPinsErrors(t *testing.T) {
	if _, _, err := planPins(nil, allPlans); err == nil {
		t.Error("no servers: want an error")
	}
	if _, _, err := planPins([]netip.Addr{netip.MustParseAddr("198.51.100.1")}, allPlans); err == nil || !strings.Contains(err.Error(), "198.51.100.1") {
		t.Errorf("unroutable server = %v, want an error naming it", err)
	}
	noLink := routes(map[string]routeInfo{"192.0.2.10": {Gateway: viaGW.Gateway}})
	if _, _, err := planPins([]netip.Addr{srv4}, noLink); err == nil {
		t.Error("route without a link: want an error")
	}
	// The zone and the 4in6 form are normalised before the lookup.
	ops, _, err := planPins([]netip.Addr{netip.MustParseAddr("::ffff:192.0.2.10")}, allPlans)
	if err != nil || ops[0].Prefix != netip.MustParsePrefix("192.0.2.10/32") {
		t.Errorf("4in6 server: %v, %v", ops, err)
	}
}

func TestPlanFullTunnelUnknownMode(t *testing.T) {
	if _, _, err := planFullTunnel(routingConfig{Mode: "auto", Tun: "wst0"}, []netip.Addr{srv4}, allPlans); err == nil {
		t.Fatal("auto must be resolved by chooseRouting before planning")
	}
}

// applying the ops and then the undo must leave nothing behind.
func TestFullTunnelUndoIsSymmetric(t *testing.T) {
	for _, rc := range []routingConfig{
		{Mode: "fwmark", Mark: 0x7774, Tun: "wst0"},
		{Mode: "pin", Tun: "wst0"},
	} {
		t.Run(rc.Mode, func(t *testing.T) {
			ops, undo, err := planFullTunnel(rc, []netip.Addr{srv4, srv6}, allPlans)
			if err != nil {
				t.Fatal(err)
			}
			rec := &recordingConfigurer{}
			if err := applyNetOps("wst0", ops, rec); err != nil {
				t.Fatal(err)
			}
			if err := runUndo(undo, rec); err != nil {
				t.Fatal(err)
			}
			state := map[string]int{}
			for _, c := range rec.calls {
				key, sign := c, 1
				switch {
				case strings.HasPrefix(c, "rule add "):
					key = "rule " + strings.TrimPrefix(c, "rule add ")
				case strings.HasPrefix(c, "rule del "):
					key, sign = "rule "+strings.TrimPrefix(c, "rule del "), -1
				case strings.HasPrefix(c, "del"):
					key, sign = strings.TrimPrefix(c, "del"), -1
				}
				state[key] += sign
			}
			for k, v := range state {
				if v != 0 {
					t.Errorf("%q left at %d after undo; calls:\n%s", k, v, strings.Join(rec.calls, "\n"))
				}
			}
		})
	}
}

func TestApplyNetOpsSkipsOnlyUnsupportedIPv6(t *testing.T) {
	ops, _, _ := planFullTunnel(routingConfig{Mode: "fwmark", Mark: 7000, Tun: "wst0"}, nil, nil)

	rec := &recordingConfigurer{failOn: "tableroute wst0 ::/0 table 7000", failErr: syscall.EAFNOSUPPORT}
	if err := applyNetOps("wst0", ops, rec); err != nil {
		t.Fatalf("IPv6 unsupported must be skipped: %v", err)
	}
	rec = &recordingConfigurer{failOn: "tableroute wst0 ::/0 table 7000", failErr: syscall.EPERM}
	if err := applyNetOps("wst0", ops, rec); err == nil {
		t.Fatal("a real IPv6 failure must abort, or IPv6 would leak")
	}
	rec = &recordingConfigurer{failOn: "tableroute wst0 0.0.0.0/0 table 7000", failErr: syscall.EAFNOSUPPORT}
	if err := applyNetOps("wst0", ops, rec); err == nil {
		t.Fatal("IPv4 failures are never skippable")
	}
}

func TestRunUndoIgnoresGoneAndKeepsGoing(t *testing.T) {
	_, undo, _ := planFullTunnel(routingConfig{Mode: "fwmark", Mark: 7000, Tun: "wst0"}, nil, nil)
	rec := &recordingConfigurer{failOn: "rule del " + undo[0].Rule.String(), failErr: syscall.ENOENT}
	if err := runUndo(undo, rec); err != nil {
		t.Fatalf("already-gone rule: %v", err)
	}
	if len(rec.calls) != len(undo) {
		t.Fatalf("undo ran %d of %d steps", len(rec.calls), len(undo))
	}
	rec = &recordingConfigurer{failOn: "rule del " + undo[1].Rule.String(), failErr: errors.New("boom")}
	err := runUndo(undo, rec)
	if err == nil || !strings.Contains(err.Error(), "boom") {
		t.Fatalf("runUndo = %v, want the failure reported", err)
	}
	if len(rec.calls) != len(undo) {
		t.Fatalf("a failure stopped the cleanup after %d of %d steps", len(rec.calls), len(undo))
	}
}

// On a host without IPv6 the kernel answers EAFNOSUPPORT when asked to remove
// an IPv6 rule or route; undo must not report that as a failure.
func TestRunUndoIgnoresAddressFamilyNotSupported(t *testing.T) {
	_, undo, _ := planFullTunnel(routingConfig{Mode: "fwmark", Mark: 7000, Tun: "wst0"}, nil, nil)
	for _, e := range []error{syscall.EAFNOSUPPORT, fmt.Errorf("delete: %w", syscall.EAFNOSUPPORT)} {
		rec := &recordingConfigurer{failOn: "rule del " + undo[0].Rule.String(), failErr: e}
		if err := runUndo(undo, rec); err != nil {
			t.Fatalf("EAFNOSUPPORT reported as a failure: %v", err)
		}
	}
	if !isGoneError(syscall.EAFNOSUPPORT) {
		t.Error("isGoneError(EAFNOSUPPORT) = false")
	}
}

func TestChooseRouting(t *testing.T) {
	servers := []netip.Addr{srv4}
	rp := func(v int, err error) func(netip.Addr) (int, error) {
		return func(netip.Addr) (int, error) { return v, err }
	}
	unreadable := errors.New("permission denied")
	for _, tc := range []struct {
		name      string
		requested string
		servers   []netip.Addr
		rp        func(netip.Addr) (int, error)
		wantMode  string
		wantErr   string
		wantWarn  bool
	}{
		{"auto, rp_filter off", "auto", servers, rp(0, nil), "fwmark", "", false},
		{"auto, loose", "auto", servers, rp(2, nil), "fwmark", "", false},
		{"auto, strict", "auto", servers, rp(1, nil), "pin", "", false},
		{"auto, unreadable falls toward pin", "auto", servers, rp(0, unreadable), "pin", "", false},
		{"auto, one strict server of two", "auto", []netip.Addr{srv4, srv4b}, func(ip netip.Addr) (int, error) {
			if ip == srv4b {
				return 1, nil
			}
			return 0, nil
		}, "pin", "", false},
		{"auto, ipv6 only", "auto", []netip.Addr{srv6}, rp(0, nil), "fwmark", "", false},
		{"fwmark, off", "fwmark", servers, rp(0, nil), "fwmark", "", false},
		{"fwmark, loose", "fwmark", servers, rp(2, nil), "fwmark", "", false},
		{"fwmark, strict is refused", "fwmark", servers, rp(1, nil), "", "rp_filter=1", false},
		{"fwmark, unreadable proceeds with a warning", "fwmark", servers, rp(0, unreadable), "fwmark", "", true},
		{"pin ignores rp_filter", "pin", servers, rp(1, nil), "pin", "", false},
		{"pin, unreadable", "pin", servers, rp(0, unreadable), "pin", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := chooseRouting(tc.requested, tc.servers, tc.rp)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) || !strings.Contains(err.Error(), "routing=pin") {
					t.Fatalf("err = %v, want an actionable error containing %q and a pointer to routing=pin", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got.Mode != tc.wantMode || (got.Warning != "") != tc.wantWarn || got.Reason == "" {
				t.Fatalf("got %+v, want mode %s warning=%v and a reason", got, tc.wantMode, tc.wantWarn)
			}
		})
	}
	if _, err := chooseRouting("bogus", servers, rp(0, nil)); err == nil {
		t.Error("unknown routing accepted")
	}
}

func TestRPFilterForUsesMaxAndSkipsIPv6(t *testing.T) {
	orig := readRPFilter
	t.Cleanup(func() { readRPFilter = orig })
	var asked []string
	readRPFilter = func(iface string) (int, error) {
		asked = append(asked, iface)
		return 2, nil
	}
	f := rpFilterFor(allPlans)
	if v, err := f(srv4); err != nil || v != 2 {
		t.Fatalf("v4 = %d, %v", v, err)
	}
	if v, err := f(srv6); err != nil || v != 0 {
		t.Fatalf("v6 = %d, %v; rp_filter does not apply to IPv6", v, err)
	}
	if !reflect.DeepEqual(asked, []string{"eth0"}) {
		t.Fatalf("read rp_filter for %v, want only the egress interface eth0", asked)
	}
	if _, err := f(netip.MustParseAddr("198.51.100.1")); err == nil {
		t.Error("unroutable server must surface as an error (unreadable)")
	}
}

func TestUniqueAddrs(t *testing.T) {
	in := []netip.Addr{srv4, netip.MustParseAddr("::ffff:192.0.2.10"), srv6, srv4}
	want := []netip.Addr{srv4, srv6}
	if got := uniqueAddrs(in); !reflect.DeepEqual(got, want) {
		t.Fatalf("uniqueAddrs = %v, want %v", got, want)
	}
}

// An exact host route to the server that the operator already owns pins the
// server on its own. Adding and later deleting it would remove the operator's
// route when the tunnel stops.
func TestPlanPinsLeavesAnExistingHostRouteAlone(t *testing.T) {
	own := viaGW
	own.ExactHost = true
	rg := routes(map[string]routeInfo{"192.0.2.10": own, "192.0.2.11": onLink})
	ops, undo, err := planPins([]netip.Addr{srv4, srv4b}, rg)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"add route 192.0.2.11/32 dev eth1"}
	if got := describeAll(ops); !reflect.DeepEqual(got, want) {
		t.Errorf("ops = %v, want %v (the operator's /32 must not be re-added)", got, want)
	}
	wantUndo := []string{"delete route 192.0.2.11/32 dev eth1"}
	if got := describeAll(undo); !reflect.DeepEqual(got, wantUndo) {
		t.Errorf("undo = %v, want %v (the operator's /32 must not be deleted)", got, wantUndo)
	}
}
