package client

import (
	"bytes"
	"context"
	cryptotls "crypto/tls"
	"errors"
	"log/slog"
	"net"
	"net/http/httptest"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/kad/wstunnel-go/pkg/tun"
	"github.com/kad/wstunnel-go/pkg/tun/tuntest"
)

type fakeDevice struct {
	tun.PacketConn
	name string
}

func (d fakeDevice) Name() string { return d.name }

// fakeHost wires startTun to a recording configurer, an in-memory device and a
// fake resolvectl, so the whole full-tunnel sequence runs without root.
type fakeHost struct {
	nl      *recordingConfigurer
	deps    tunDeps
	host    *tuntest.Host
	devPeer tun.PacketConn
	opened  int

	mu         sync.Mutex
	resolvectl [][]string
	noResolve  bool
	// resolvectlHook, when set, decides the result of each resolvectl call.
	resolvectlHook func(ctx context.Context, args []string) error
}

func newFakeHost(t *testing.T, serverHost string) *fakeHost {
	t.Helper()
	devEnd, hostEnd := tuntest.Pipe()
	f := &fakeHost{
		nl: &recordingConfigurer{routes: routes(map[string]routeInfo{
			serverHost: {Gateway: netip.MustParseAddr("10.200.0.2"), Link: "eth0"},
		})},
		devPeer: hostEnd,
		host:    tuntest.NewHost(t, hostEnd, 1500),
	}
	f.deps = tunDeps{
		// Without CAP_NET_ADMIN the real SO_MARK fails, which a full tunnel now
		// treats as fatal for the dial; the fake host pretends it works.
		setMark:    func(uintptr, uint32) error { return nil },
		openDevice: func(string) (tunDevice, error) { f.opened++; return fakeDevice{devEnd, "wst0"}, nil },
		deviceMTU:  func(string) (int, error) { return 1500, nil },
		nl:         f.nl,
		lookPath: func(file string) (string, error) {
			if f.noResolve {
				return "", errors.New("not found")
			}
			return "/usr/bin/" + file, nil
		},
		runCmd: func(ctx context.Context, name string, args ...string) error {
			f.mu.Lock()
			f.resolvectl = append(f.resolvectl, append([]string{name}, args...))
			hook := f.resolvectlHook
			f.mu.Unlock()
			_ = f.nl.record("resolvectl " + args[0])
			if hook != nil {
				return hook(ctx, args)
			}
			return nil
		},
	}
	orig := readRPFilter
	t.Cleanup(func() { readRPFilter = orig })
	readRPFilter = func(string) (int, error) { return 0, nil }
	return f
}

func (f *fakeHost) resolvectlCalls() [][]string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.resolvectl)
}

func startFullTunnel(t *testing.T, f *fakeHost, cfg Config, arg string) (*Client, *TunHandle) {
	t.Helper()
	c := NewClient(cfg)
	h, err := c.startTun(context.Background(), mustSpec(t, arg), f.deps, fastRetry)
	if err != nil {
		t.Fatalf("startTun: %v", err)
	}
	t.Cleanup(func() { _ = h.Close() })
	return c, h
}

func indexOf(calls []string, prefix string) int {
	return slices.IndexFunc(calls, func(c string) bool { return strings.HasPrefix(c, prefix) })
}

func TestFullTunnelFwmarkRuntime(t *testing.T) {
	srv := newTestTunServer(t, "rust", "")
	host, _, _ := net.SplitHostPort(srv.addr)
	f := newFakeHost(t, host)
	c, h := startFullTunnel(t, f, Config{ServerURL: "ws://" + srv.addr, PathPrefix: "v1", WebsocketProtocol: "rust"},
		"tun://wst0?route=default&routing=fwmark&dns=1.1.1.1&dns=9.9.9.9")

	if c.socketMark() != 0x7774 {
		t.Errorf("socket mark = %#x; the client's sockets must carry the mark even without --socket-so-mark", c.socketMark())
	}
	if c.resolver.Load() == nil {
		t.Error("no marked resolver in fwmark mode")
	}
	calls := f.nl.snapshot()
	order := []string{"routeget " + host, "listrules 4", "listrules 6", "mtu wst0", "up wst0", "tableroute wst0 0.0.0.0/0 table 30580", "rule add ipv4 pref 32760", "rule add ipv4 pref 32761"}
	prev := -1
	for _, want := range order {
		i := indexOf(calls, want)
		if i < 0 || i < prev {
			t.Fatalf("calls out of order or missing %q:\n%s", want, strings.Join(calls, "\n"))
		}
		prev = i
	}
	wantCmds := [][]string{
		{"/usr/bin/resolvectl", "dns", "wst0", "1.1.1.1", "9.9.9.9"},
		{"/usr/bin/resolvectl", "domain", "wst0", "~."},
	}
	if got := f.resolvectlCalls(); !slices.EqualFunc(got, wantCmds, slices.Equal) {
		t.Fatalf("resolvectl calls = %v, want %v", got, wantCmds)
	}

	// The tunnel actually carries traffic.
	waitEcho(t, f.host, "full tunnel")

	if err := h.Close(); err != nil {
		t.Fatal(err)
	}
	after := f.nl.snapshot()[len(calls):]
	for _, want := range []string{"rule del ipv6 pref 32761", "rule del ipv6 pref 32760", "rule del ipv4 pref 32761", "rule del ipv4 pref 32760", "deltableroute wst0 ::/0", "deltableroute wst0 0.0.0.0/0"} {
		if indexOf(after, want) < 0 {
			t.Errorf("Close did not run %q; calls after start:\n%s", want, strings.Join(after, "\n"))
		}
	}
	f.nl.mu.Lock()
	left := len(f.nl.existingRules)
	f.nl.mu.Unlock()
	if left != 0 {
		t.Errorf("%d rules left installed after Close", left)
	}
	got := f.resolvectlCalls()
	if last := got[len(got)-1]; !slices.Equal(last, []string{"/usr/bin/resolvectl", "revert", "wst0"}) {
		t.Errorf("last resolvectl call = %v, want revert", last)
	}
}

func TestFullTunnelCleansUpWhenTheDeviceFails(t *testing.T) {
	srv := newTestTunServer(t, "rust", "")
	host, _, _ := net.SplitHostPort(srv.addr)
	f := newFakeHost(t, host)
	_, h := startFullTunnel(t, f, Config{ServerURL: "ws://" + srv.addr, PathPrefix: "v1", WebsocketProtocol: "rust"}, "tun://wst0?route=default&routing=fwmark")

	_ = f.devPeer.Close() // the device disappears
	select {
	case <-h.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("Done did not fire")
	}
	if h.Err() == nil {
		t.Fatal("device failure must be a fatal error")
	}
	f.nl.mu.Lock()
	defer f.nl.mu.Unlock()
	if len(f.nl.existingRules) != 0 {
		t.Fatalf("rules left after a fatal device error: %v", f.nl.existingRules)
	}
}

func TestFullTunnelPinInstallsAndRefreshesEveryAttempt(t *testing.T) {
	srv := newTestTunServer(t, "rust", "")
	host, _, _ := net.SplitHostPort(srv.addr)
	f := newFakeHost(t, host)
	c, h := startFullTunnel(t, f, Config{ServerURL: "ws://" + srv.addr, PathPrefix: "v1", WebsocketProtocol: "rust"}, "tun://wst0?route=default&routing=pin")
	if c.resolver.Load() != nil || c.socketMark() != 0 {
		t.Error("pin mode must not need marked sockets or a marked resolver")
	}
	pin := "hostroute " + host + "/32 via 10.200.0.2 dev eth0"
	calls := f.nl.snapshot()
	if i, j := indexOf(calls, pin), indexOf(calls, "route wst0 0.0.0.0/1"); i < 0 || j < 0 || i > j {
		t.Fatalf("the pin must be installed before the /1 halves:\n%s", strings.Join(calls, "\n"))
	}

	// Drop the connection repeatedly: every attempt must delete the old pin,
	// look the real route up avoiding the tunnel, and add the pin again.
	stop := make(chan struct{})
	var stopOnce sync.Once
	stopDropping := func() { stopOnce.Do(func() { close(stop) }) }
	go func() {
		for {
			select {
			case <-stop:
				return
			case <-time.After(15 * time.Millisecond):
				srv.ln.closeAll()
			}
		}
	}()
	t.Cleanup(stopDropping)
	deadline := time.Now().Add(10 * time.Second)
	count := func() int {
		n := 0
		for _, c := range f.nl.snapshot() {
			if c == "routeget "+host+" avoid wst0" {
				n++
			}
		}
		return n
	}
	for count() < 4 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if count() < 4 {
		t.Fatalf("only %d re-pins after reconnects", count())
	}
	all := f.nl.snapshot()
	// Each refresh is the triple delete, routeget, add.
	for i, c := range all {
		if i >= len(calls) && c == "routeget "+host+" avoid wst0" {
			if !strings.HasPrefix(all[i-1], "delhostroute "+host+"/32") || !strings.HasPrefix(all[i+1], "hostroute "+host+"/32") {
				t.Fatalf("refresh around call %d is not delete, routeget, add:\n%s", i, strings.Join(all[max(0, i-2):min(len(all), i+3)], "\n"))
			}
		}
	}

	stopDropping()
	if err := h.Close(); err != nil {
		t.Fatal(err)
	}
	final := f.nl.snapshot()
	tail := final[len(final)-8:]
	for _, want := range []string{"delroute wst0 8000::/1", "delroute wst0 0.0.0.0/1", "delhostroute " + host + "/32"} {
		if indexOf(final, want) < 0 {
			t.Errorf("cleanup missing %q; tail:\n%s", want, strings.Join(tail, "\n"))
		}
	}
	if last := final[len(final)-1]; !strings.HasPrefix(last, "delhostroute") {
		t.Errorf("the pins must be removed last (after the /1 halves); last call %q", last)
	}
}

func TestFullTunnelRefusesExplicitFwmarkWithStrictRPFilter(t *testing.T) {
	srv := newTestTunServer(t, "rust", "")
	host, _, _ := net.SplitHostPort(srv.addr)
	f := newFakeHost(t, host)
	readRPFilter = func(string) (int, error) { return 1, nil }
	c := NewClient(Config{ServerURL: "ws://" + srv.addr, PathPrefix: "v1", WebsocketProtocol: "rust"})
	_, err := c.startTun(context.Background(), mustSpec(t, "tun://wst0?route=default&routing=fwmark"), f.deps, fastRetry)
	if err == nil || !strings.Contains(err.Error(), "rp_filter=1") || !strings.Contains(err.Error(), "routing=pin") {
		t.Fatalf("err = %v, want the actionable rp_filter refusal", err)
	}
	if f.opened != 0 {
		t.Error("a device was created before the refusal")
	}
	for _, c := range f.nl.snapshot() {
		if !strings.HasPrefix(c, "routeget") {
			t.Errorf("host was modified before the refusal: %q", c)
		}
	}
	if c.socketMark() != 0 {
		t.Error("the mark was armed although startup was refused")
	}
}

func TestFullTunnelAutoPicksPinUnderStrictRPFilter(t *testing.T) {
	srv := newTestTunServer(t, "rust", "")
	host, _, _ := net.SplitHostPort(srv.addr)
	f := newFakeHost(t, host)
	readRPFilter = func(iface string) (int, error) {
		if iface != "eth0" {
			t.Errorf("rp_filter read for %q, want the egress interface eth0", iface)
		}
		return 1, nil
	}
	_, _ = startFullTunnel(t, f, Config{ServerURL: "ws://" + srv.addr, PathPrefix: "v1", WebsocketProtocol: "rust"}, "tun://wst0?route=default")
	calls := f.nl.snapshot()
	if indexOf(calls, "hostroute "+host) < 0 || indexOf(calls, "rule add") >= 0 {
		t.Fatalf("auto under strict rp_filter must pin, not install rules:\n%s", strings.Join(calls, "\n"))
	}
}

func TestFullTunnelUsesGivenSocketMarkAsTable(t *testing.T) {
	srv := newTestTunServer(t, "rust", "")
	host, _, _ := net.SplitHostPort(srv.addr)
	f := newFakeHost(t, host)
	c, _ := startFullTunnel(t, f, Config{ServerURL: "ws://" + srv.addr, PathPrefix: "v1", WebsocketProtocol: "rust", SocketSoMark: 4242}, "tun://wst0?route=default&routing=fwmark")
	if c.socketMark() != 4242 || indexOf(f.nl.snapshot(), "tableroute wst0 0.0.0.0/0 table 4242") < 0 {
		t.Fatalf("mark = %d, calls:\n%s", c.socketMark(), strings.Join(f.nl.snapshot(), "\n"))
	}
}

func TestFullTunnelRefusesConnectionPool(t *testing.T) {
	f := newFakeHost(t, "127.0.0.1")
	c := NewClient(Config{ServerURL: "ws://127.0.0.1:1", PathPrefix: "v1", ConnectionMinIdle: 1})
	t.Cleanup(func() { c.pool.cancel() })
	if _, err := c.startTun(context.Background(), mustSpec(t, "tun://wst0?route=default"), f.deps, fastRetry); err == nil || !strings.Contains(err.Error(), "connection_min_idle") {
		t.Fatalf("err = %v, want a refusal naming connection_min_idle", err)
	}
}

func TestFullTunnelSetupFailureRollsBack(t *testing.T) {
	srv := newTestTunServer(t, "rust", "")
	host, _, _ := net.SplitHostPort(srv.addr)
	f := newFakeHost(t, host)
	f.nl.failOn = "rule add ipv4 pref 32761 not fwmark 0x7774 table 30580"
	f.nl.failErr = syscall.EPERM
	c := NewClient(Config{ServerURL: "ws://" + srv.addr, PathPrefix: "v1", WebsocketProtocol: "rust"})
	if _, err := c.startTun(context.Background(), mustSpec(t, "tun://wst0?route=default&routing=fwmark"), f.deps, fastRetry); err == nil {
		t.Fatal("startTun succeeded although a rule could not be installed")
	}
	f.nl.mu.Lock()
	defer f.nl.mu.Unlock()
	if len(f.nl.existingRules) != 0 {
		t.Fatalf("rules left after a failed setup: %v", f.nl.existingRules)
	}
	if indexOf(f.nl.calls, "deltableroute wst0 0.0.0.0/0") < 0 {
		t.Errorf("table route not removed after a failed setup:\n%s", strings.Join(f.nl.calls, "\n"))
	}
}

// wgQuickRules are the rules wg-quick installs for a full-tunnel WireGuard
// interface (fwmark 51820): they must survive our startup untouched.
func wgQuickRules(family int) []ruleSpec {
	return []ruleSpec{
		{Family: family, Priority: 32764, Table: 254, Suppress: 0},
		{Family: family, Priority: 32765, Table: 51820, Mark: 51820, NotMark: true, Suppress: -1},
	}
}

func TestFullTunnelLeavesWgQuickRulesAlone(t *testing.T) {
	srv := newTestTunServer(t, "rust", "")
	host, _, _ := net.SplitHostPort(srv.addr)
	f := newFakeHost(t, host)
	wg := slices.Concat(wgQuickRules(4), wgQuickRules(6))
	f.nl.existingRules = slices.Clone(wg)
	c := NewClient(Config{ServerURL: "ws://" + srv.addr, PathPrefix: "v1", WebsocketProtocol: "rust"})
	h, err := c.startTun(context.Background(), mustSpec(t, "tun://wst0?route=default&routing=fwmark"), f.deps, fastRetry)
	if err != nil {
		t.Fatalf("startTun: %v", err)
	}
	f.nl.mu.Lock()
	have := slices.Clone(f.nl.existingRules)
	f.nl.mu.Unlock()
	for _, r := range wg {
		if !slices.Contains(have, r) {
			t.Errorf("another program's rule was removed: %s", r)
		}
	}
	if err := h.Close(); err != nil {
		t.Fatal(err)
	}
	f.nl.mu.Lock()
	defer f.nl.mu.Unlock()
	if !slices.Equal(f.nl.existingRules, wg) {
		t.Fatalf("rules after Close = %v, want exactly the other program's %v", f.nl.existingRules, wg)
	}
}

func TestPurgeStaleRules(t *testing.T) {
	ours := fullTunnelRules(4, 0x7774)
	ours6 := fullTunnelRules(6, 0x7774)
	foreign := slices.Concat([]ruleSpec{
		{Family: 4, Priority: 0, Table: 255, Suppress: -1},
		{Family: 4, Priority: 32766, Table: 254, Suppress: -1},
		{Family: 4, Priority: 100, Table: 5, Suppress: -1},
	}, wgQuickRules(4), wgQuickRules(6))
	stale := slices.Concat(foreign, ours, ours6, []ruleSpec{ours[0]}) // one duplicated
	nl := &recordingConfigurer{existingRules: stale}
	if err := purgeStaleRules(nl, 0x7774); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(nl.existingRules, foreign) {
		t.Fatalf("rules after purge = %v, want only the foreign ones %v", nl.existingRules, foreign)
	}
}

func TestPurgeRefusesRulesOfAnotherMark(t *testing.T) {
	for name, other := range map[string]ruleSpec{
		"another mark at our catch-all priority": {Family: 4, Priority: rulePrioMark, Table: 99, Mark: 99, NotMark: true, Suppress: -1},
		"foreign rule at our suppress priority":  {Family: 6, Priority: rulePrioSuppress, Table: 100, Suppress: -1},
		"foreign rule at our catch-all priority": {Family: 4, Priority: rulePrioMark, Table: 254, Suppress: -1},
	} {
		t.Run(name, func(t *testing.T) {
			before := slices.Concat(fullTunnelRules(4, 0x7774), []ruleSpec{other})
			nl := &recordingConfigurer{existingRules: slices.Clone(before)}
			err := purgeStaleRules(nl, 0x7774)
			if err == nil {
				t.Fatal("purge accepted a rule of another mark")
			}
			for _, want := range []string{"ip rule del", "another full tunnel"} {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("error %q lacks %q", err, want)
				}
			}
			if !slices.Equal(nl.existingRules, before) {
				t.Errorf("refusal must not delete anything: %v", nl.existingRules)
			}
		})
	}
}

func TestFullTunnelRefusesWhenAnotherFullTunnelIsActive(t *testing.T) {
	srv := newTestTunServer(t, "rust", "")
	host, _, _ := net.SplitHostPort(srv.addr)
	f := newFakeHost(t, host)
	f.nl.existingRules = []ruleSpec{{Family: 4, Priority: rulePrioMark, Table: 99, Mark: 99, NotMark: true, Suppress: -1}}
	c := NewClient(Config{ServerURL: "ws://" + srv.addr, PathPrefix: "v1", WebsocketProtocol: "rust"})
	_, err := c.startTun(context.Background(), mustSpec(t, "tun://wst0?route=default&routing=fwmark"), f.deps, fastRetry)
	if err == nil || !strings.Contains(err.Error(), "ip rule del") {
		t.Fatalf("err = %v, want an actionable refusal", err)
	}
	if f.opened != 0 {
		t.Error("a device was created before the refusal")
	}
}

func TestFullTunnelPinModeNeverTouchesRules(t *testing.T) {
	srv := newTestTunServer(t, "rust", "")
	host, _, _ := net.SplitHostPort(srv.addr)
	f := newFakeHost(t, host)
	stale := fullTunnelRules(4, 0x7774)
	f.nl.existingRules = slices.Clone(stale)
	_, _ = startFullTunnel(t, f, Config{ServerURL: "ws://" + srv.addr, PathPrefix: "v1", WebsocketProtocol: "rust"}, "tun://wst0?route=default&routing=pin")
	if i := indexOf(f.nl.snapshot(), "listrules"); i >= 0 {
		t.Errorf("pin mode looked at the rules: %s", f.nl.snapshot()[i])
	}
	f.nl.mu.Lock()
	defer f.nl.mu.Unlock()
	if !slices.Equal(f.nl.existingRules, stale) {
		t.Errorf("pin mode changed the rules: %v", f.nl.existingRules)
	}
}

func TestPurgeSkipsIPv6WhenUnsupported(t *testing.T) {
	nl := &unsupportedV6Lister{}
	if err := purgeStaleRules(nl, 1); err != nil {
		t.Fatalf("an IPv6-less kernel must not fail the purge: %v", err)
	}
}

type unsupportedV6Lister struct{ recordingConfigurer }

func (u *unsupportedV6Lister) ListRules(family int) ([]ruleSpec, error) {
	if family == 6 {
		return nil, syscall.EAFNOSUPPORT
	}
	return nil, nil
}

func TestConfigureDNS(t *testing.T) {
	var calls [][]string
	deps := tunDeps{
		lookPath: func(string) (string, error) { return "/bin/resolvectl", nil },
		runCmd: func(_ context.Context, name string, args ...string) error {
			calls = append(calls, append([]string{name}, args...))
			return nil
		},
	}
	revert := configureDNS(context.Background(), deps, "wst0", []netip.Addr{netip.MustParseAddr("1.1.1.1"), netip.MustParseAddr("2606:4700:4700::1111")})
	want := [][]string{
		{"/bin/resolvectl", "dns", "wst0", "1.1.1.1", "2606:4700:4700::1111"},
		{"/bin/resolvectl", "domain", "wst0", "~."},
	}
	if !slices.EqualFunc(calls, want, slices.Equal) {
		t.Fatalf("calls = %v, want %v", calls, want)
	}
	_ = revert()
	if last := calls[len(calls)-1]; !slices.Equal(last, []string{"/bin/resolvectl", "revert", "wst0"}) {
		t.Fatalf("revert call = %v", last)
	}

	calls = nil
	configureDNS(context.Background(), deps, "wst0", nil)
	if len(calls) != 0 {
		t.Fatalf("no dns= must not run resolvectl: %v", calls)
	}
}

func TestConfigureDNSWithoutResolvectlWarns(t *testing.T) {
	var buf syncBuffer
	old := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, nil)))
	t.Cleanup(func() { slog.SetDefault(old) })

	ran := false
	deps := tunDeps{
		lookPath: func(string) (string, error) { return "", errors.New("not found") },
		runCmd:   func(context.Context, string, ...string) error { ran = true; return nil },
	}
	revert := configureDNS(context.Background(), deps, "wst0", []netip.Addr{netip.MustParseAddr("1.1.1.1")})
	if ran {
		t.Error("ran a command although resolvectl is absent")
	}
	if !strings.Contains(buf.String(), "level=WARN") || !strings.Contains(buf.String(), "resolvectl") {
		t.Errorf("log = %q, want a warning mentioning resolvectl", buf.String())
	}
	if err := revert(); err != nil {
		t.Errorf("revert = %v", err)
	}
}

func TestMarkedDialerAppliesTheMark(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pc.Close() })
	var gotMark uint32
	var calls int
	dial := markedDialer(0xbeef, func(fd uintptr, mark uint32) error {
		calls++
		gotMark = mark
		if fd == 0 {
			t.Error("setMark called without a socket")
		}
		return nil
	})
	conn, err := dial(context.Background(), "udp", pc.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()
	if calls != 1 || gotMark != 0xbeef {
		t.Fatalf("setMark calls = %d mark = %#x, want one call with 0xbeef", calls, gotMark)
	}

	// A failing setsockopt must fail the dial: an unmarked DNS query would go
	// into the tunnel.
	dial = markedDialer(1, func(uintptr, uint32) error { return syscall.EPERM })
	if conn, err := dial(context.Background(), "udp", pc.LocalAddr().String()); err == nil {
		_ = conn.Close()
		t.Fatal("dial succeeded although the mark could not be set")
	}
}

func TestResolverFallsBackToLastKnownAddresses(t *testing.T) {
	// The marked resolver cannot reach any DNS server (the tunnel is down and so
	// is the path): the guard must carry on with the addresses it knew.
	c := NewClient(Config{ServerURL: "wss://tun.example.test"})
	c.resolver.Store(&net.Resolver{PreferGo: true, Dial: func(context.Context, string, string) (net.Conn, error) {
		return nil, errors.New("dns unreachable")
	}})
	known := []netip.Addr{netip.MustParseAddr("203.0.113.5")}
	servers := c.newTunServers(mustSpec(t, "tun://wst0?route=default"), known)
	got, err := servers.refresh(context.Background())
	if err != nil || !slices.Equal(got, known) {
		t.Fatalf("refresh = %v, %v; want the last known %v", got, err, known)
	}
	// And with nothing known it fails closed.
	servers = c.newTunServers(mustSpec(t, "tun://wst0?route=default"), nil)
	if _, err := servers.refresh(context.Background()); err == nil {
		t.Fatal("no known address and no DNS must fail closed")
	}
}

// TestFullTunnelDialsCachedAddressesWhenDNSIsDown starts a full tunnel against
// a server named by a host name that does not resolve for the dial (only the
// first lookup, made at start, succeeds). Every later connect must use the
// cached address, and the name must still be what TLS sends as SNI.
func TestFullTunnelDialsCachedAddressesWhenDNSIsDown(t *testing.T) {
	const name = "tun-server.invalid"
	for _, tc := range []struct{ name, mode, scheme string }{
		{"rust websocket cleartext", "rust", "ws"},
		{"rust websocket tls", "rust", "wss"},
		{"rfc6455 websocket cleartext", "ws", "ws"},
		{"rfc6455 websocket tls", "ws", "wss"},
		{"http2 cleartext", "rust", "http"},
		{"http2 tls", "rust", "https"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tls := tc.scheme == "wss" || tc.scheme == "https"
			var sni atomic.Value
			srv := newTestTunServerTLS(t, tc.mode, "", tls, func(s *httptest.Server) {
				s.TLS = &cryptotls.Config{GetConfigForClient: func(h *cryptotls.ClientHelloInfo) (*cryptotls.Config, error) {
					sni.Store(h.ServerName)
					return nil, nil
				}}
			})
			_, port, _ := net.SplitHostPort(srv.addr)

			orig := lookupNetIP
			t.Cleanup(func() { lookupNetIP = orig })
			var lookups atomic.Int32
			lookupNetIP = func(context.Context, string) ([]netip.Addr, error) {
				if lookups.Add(1) == 1 {
					return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
				}
				return nil, errors.New("dns down")
			}

			f := newFakeHost(t, "127.0.0.1")
			startFullTunnel(t, f, Config{ServerURL: tc.scheme + "://" + net.JoinHostPort(name, port), PathPrefix: "v1", WebsocketProtocol: tc.mode},
				"tun://wst0?route=default&routing=pin")
			waitEcho(t, f.host, "first")
			// Drop the session: the reconnect runs with the resolver down.
			srv.ln.closeAll()
			waitEcho(t, f.host, "after reconnect")
			if n := lookups.Load(); n < 3 {
				t.Errorf("only %d lookups; the reconnect did not go through the failing resolver", n)
			}
			if tls {
				if got, _ := sni.Load().(string); got != name {
					t.Errorf("TLS SNI = %q, want the server name %q", got, name)
				}
			}
		})
	}
}

func TestPinnedTargets(t *testing.T) {
	c := NewClient(Config{ServerURL: "wss://tun.example.test:8443"})
	if got := c.pinnedTargets("tun.example.test:8443"); got != nil {
		t.Fatalf("targets before any address is cached = %v", got)
	}
	c.serverAddrs.Store(&[]netip.Addr{netip.MustParseAddr("203.0.113.5"), netip.MustParseAddr("2001:db8::1")})
	want := []string{"203.0.113.5:8443", "[2001:db8::1]:8443"}
	if got := c.pinnedTargets("TUN.example.test:8443"); !slices.Equal(got, want) {
		t.Errorf("targets = %v, want %v, in order", got, want)
	}
	if got := c.pinnedTargets("other.example.test:8443"); got != nil {
		t.Errorf("another host must resolve normally, got %v", got)
	}
}

func TestFullTunnelRefusesAnExistingDevice(t *testing.T) {
	srv := newTestTunServer(t, "rust", "")
	host, _, _ := net.SplitHostPort(srv.addr)
	f := newFakeHost(t, host)
	f.nl.existingRules = fullTunnelRules(4, 0x7774) // would be purged if the start got that far
	before := slices.Clone(f.nl.existingRules)
	f.deps.ifaceExists = func(name string) bool { return name == "wst0" }
	c := NewClient(Config{ServerURL: "ws://" + srv.addr, PathPrefix: "v1", WebsocketProtocol: "rust"})
	_, err := c.startTun(context.Background(), mustSpec(t, "tun://wst0?route=default&routing=fwmark"), f.deps, fastRetry)
	if err == nil {
		t.Fatal("route=default accepted a device that already exists")
	}
	for _, want := range []string{"wst0", "already exists", "disappears with the process"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q lacks %q", err, want)
		}
	}
	if f.opened != 0 || len(f.nl.snapshot()) != 0 || !slices.Equal(f.nl.existingRules, before) {
		t.Errorf("the host was touched before the refusal: opened=%d calls=%v", f.opened, f.nl.snapshot())
	}
	if c.fullTunnelMark.Load() != 0 {
		t.Error("the mark was armed before the refusal")
	}

	// Another name, and no name at all, are fine.
	for _, arg := range []string{"tun://wst1?route=default&routing=fwmark", "tun://?route=default&routing=fwmark"} {
		c := NewClient(Config{ServerURL: "ws://" + srv.addr, PathPrefix: "v1", WebsocketProtocol: "rust"})
		f2 := newFakeHost(t, host)
		f2.deps.ifaceExists = f.deps.ifaceExists
		h, err := c.startTun(context.Background(), mustSpec(t, arg), f2.deps, fastRetry)
		if err != nil {
			t.Fatalf("%s: %v", arg, err)
		}
		_ = h.Close()
	}
}

func TestSplitRouteTunStillAttachesToAnExistingDevice(t *testing.T) {
	srv := newTestTunServer(t, "rust", "")
	host, _, _ := net.SplitHostPort(srv.addr)
	f := newFakeHost(t, host)
	f.deps.ifaceExists = func(string) bool { return true }
	c := NewClient(Config{ServerURL: "ws://" + srv.addr, PathPrefix: "v1", WebsocketProtocol: "rust"})
	h, err := c.startTun(context.Background(), mustSpec(t, "tun://wst0?route=10.0.0.0/8"), f.deps, fastRetry)
	if err != nil {
		t.Fatalf("a split-route tunnel must keep working with an existing device: %v", err)
	}
	_ = h.Close()
}

// failSoMark makes every SO_MARK attempt of c fail.
func failSoMark(c *Client) {
	c.setMark = func(uintptr, uint32) error { return syscall.EPERM }
}

func listenAccepting(t *testing.T) (addr string, accepted *atomic.Int32) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	accepted = new(atomic.Int32)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			accepted.Add(1)
			_ = c.Close()
		}
	}()
	return ln.Addr().String(), accepted
}

func TestFullTunnelDialFailsWhenTheMarkCannotBeSet(t *testing.T) {
	addr, accepted := listenAccepting(t)

	c := NewClient(Config{ServerURL: "ws://" + addr})
	failSoMark(c)
	c.fullTunnelMark.Store(0x7774)
	conn, _, _, err := c.dialRawTransport(context.Background(), "tcp", addr)
	if err == nil {
		_ = conn.Close()
		t.Fatal("the dial connected although the full-tunnel mark could not be set")
	}
	if !errors.Is(err, syscall.EPERM) || !strings.Contains(err.Error(), "SO_MARK") {
		t.Errorf("error %q does not say that setting the mark failed", err)
	}
	time.Sleep(50 * time.Millisecond)
	if n := accepted.Load(); n != 0 {
		t.Errorf("the server saw %d unmarked connections", n)
	}
}

func TestPlainSocketMarkStaysBestEffort(t *testing.T) {
	addr, _ := listenAccepting(t)
	c := NewClient(Config{ServerURL: "ws://" + addr, SocketSoMark: 5})
	failSoMark(c)
	conn, _, _, err := c.dialRawTransport(context.Background(), "tcp", addr)
	if err != nil {
		t.Fatalf("--socket-so-mark outside a full tunnel is best effort, got %v", err)
	}
	_ = conn.Close()
}

func TestFullTunnelWebTransportDialFailsWhenTheMarkCannotBeSet(t *testing.T) {
	c := NewClient(Config{ServerURL: "wts://127.0.0.1:9"})
	failSoMark(c)
	c.fullTunnelMark.Store(0x7774)
	w := NewWebTransportClient(c)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_, err := w.dialMarkedAddr(ctx, "127.0.0.1:9", &cryptotls.Config{InsecureSkipVerify: true}, newWebTransportQUICConfig())
	if err == nil || !strings.Contains(err.Error(), "SO_MARK") {
		t.Fatalf("err = %v, want a failure to set SO_MARK before any packet is sent", err)
	}
}

func TestPlainSocketMarkWebTransportStaysBestEffort(t *testing.T) {
	c := NewClient(Config{ServerURL: "wts://127.0.0.1:9", SocketSoMark: 5})
	failSoMark(c)
	w := NewWebTransportClient(c)
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	_, err := w.dialMarkedAddr(ctx, "127.0.0.1:9", &cryptotls.Config{InsecureSkipVerify: true}, newWebTransportQUICConfig())
	if err != nil && strings.Contains(err.Error(), "SO_MARK") {
		t.Fatalf("a failed mark must not fail a non-tun dial: %v", err)
	}
}

func TestFullTunnelConfiguresDNSBeforeCapturingTheHost(t *testing.T) {
	srv := newTestTunServer(t, "rust", "")
	host, _, _ := net.SplitHostPort(srv.addr)
	f := newFakeHost(t, host)
	startFullTunnel(t, f, Config{ServerURL: "ws://" + srv.addr, PathPrefix: "v1", WebsocketProtocol: "rust"},
		"tun://wst0?route=default&routing=fwmark&dns=1.1.1.1")
	calls := f.nl.snapshot()
	up, dns, domain, route, rule := indexOf(calls, "up wst0"), indexOf(calls, "resolvectl dns"), indexOf(calls, "resolvectl domain"),
		indexOf(calls, "tableroute"), indexOf(calls, "rule add")
	if up < 0 || dns < 0 || domain < 0 || route < 0 || rule < 0 {
		t.Fatalf("missing steps in:\n%s", strings.Join(calls, "\n"))
	}
	if up >= dns || dns >= domain || domain >= route || route >= rule {
		t.Fatalf("DNS must be configured after the link is up and before any route or rule captures the host:\n%s", strings.Join(calls, "\n"))
	}
}

func TestFullTunnelHungResolvectlIsBoundedAndNotFatal(t *testing.T) {
	srv := newTestTunServer(t, "rust", "")
	host, _, _ := net.SplitHostPort(srv.addr)
	f := newFakeHost(t, host)
	f.deps.dnsTimeout = 100 * time.Millisecond
	f.resolvectlHook = func(ctx context.Context, _ []string) error {
		<-ctx.Done() // a resolver that never answers
		return ctx.Err()
	}
	var buf syncBuffer
	old := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, nil)))
	t.Cleanup(func() { slog.SetDefault(old) })

	begin := time.Now()
	_, h := startFullTunnel(t, f, Config{ServerURL: "ws://" + srv.addr, PathPrefix: "v1", WebsocketProtocol: "rust"},
		"tun://wst0?route=default&routing=fwmark&dns=1.1.1.1")
	if d := time.Since(begin); d > 3*time.Second {
		t.Errorf("startup took %v with a hung resolvectl", d)
	}
	waitEcho(t, f.host, "dns hung")
	begin = time.Now()
	if err := h.Close(); err != nil {
		t.Fatalf("a hung resolvectl must not make Close fail: %v", err)
	}
	if d := time.Since(begin); d > 3*time.Second {
		t.Errorf("Close took %v with a hung resolvectl", d)
	}
	if !strings.Contains(buf.String(), "level=WARN") || !strings.Contains(buf.String(), "resolvectl") {
		t.Errorf("no warning about resolvectl in %q", buf.String())
	}
	f.nl.mu.Lock()
	defer f.nl.mu.Unlock()
	if len(f.nl.existingRules) != 0 {
		t.Errorf("rules left after Close: %v", f.nl.existingRules)
	}
}

func TestFullTunnelRevertsDNSWhenTheRoutingCannotBeInstalled(t *testing.T) {
	srv := newTestTunServer(t, "rust", "")
	host, _, _ := net.SplitHostPort(srv.addr)
	f := newFakeHost(t, host)
	f.nl.failOn = "rule add ipv4 pref 32761 not fwmark 0x7774 table 30580"
	f.nl.failErr = syscall.EPERM
	c := NewClient(Config{ServerURL: "ws://" + srv.addr, PathPrefix: "v1", WebsocketProtocol: "rust"})
	if _, err := c.startTun(context.Background(), mustSpec(t, "tun://wst0?route=default&routing=fwmark&dns=1.1.1.1"), f.deps, fastRetry); err == nil {
		t.Fatal("startTun succeeded although a rule could not be installed")
	}
	got := f.resolvectlCalls()
	if len(got) == 0 || !slices.Equal(got[len(got)-1], []string{"/usr/bin/resolvectl", "revert", "wst0"}) {
		t.Fatalf("resolvectl calls = %v, want a final revert", got)
	}
}

func TestConfigureDNSEachCommandHasADeadline(t *testing.T) {
	if got := defaultTunDeps().dnsTimeout; got != 10*time.Second {
		t.Errorf("default resolvectl timeout = %v, want 10s", got)
	}
	var deadlines []time.Duration
	deps := tunDeps{
		lookPath: func(string) (string, error) { return "/bin/resolvectl", nil },
		runCmd: func(ctx context.Context, _ string, _ ...string) error {
			dl, ok := ctx.Deadline()
			if !ok {
				t.Error("resolvectl ran without a deadline")
			}
			deadlines = append(deadlines, time.Until(dl))
			return nil
		},
		dnsTimeout: 2 * time.Second,
	}
	revert := configureDNS(context.Background(), deps, "wst0", []netip.Addr{netip.MustParseAddr("1.1.1.1")})
	_ = revert()
	if len(deadlines) != 3 {
		t.Fatalf("%d commands, want dns, domain and revert", len(deadlines))
	}
	for _, d := range deadlines {
		if d <= 0 || d > 2*time.Second {
			t.Errorf("deadline in %v, want within 2s", d)
		}
	}
}

// A start that fails after the client's sockets were armed must not leave the
// mark, the marked resolver or the cached server addresses behind: the client
// can be used for other tunnels afterwards.
func TestFailedFullTunnelStartResetsTheClient(t *testing.T) {
	srv := newTestTunServer(t, "rust", "")
	host, _, _ := net.SplitHostPort(srv.addr)
	f := newFakeHost(t, host)
	f.nl.failOn = "rule add ipv4 pref 32761 not fwmark 0x7774 table 30580"
	f.nl.failErr = syscall.EPERM
	c := NewClient(Config{ServerURL: "ws://" + srv.addr, PathPrefix: "v1", WebsocketProtocol: "rust"})
	if _, err := c.startTun(context.Background(), mustSpec(t, "tun://wst0?route=default&routing=fwmark"), f.deps, fastRetry); err == nil {
		t.Fatal("startTun succeeded although a rule could not be installed")
	}
	if m := c.fullTunnelMark.Load(); m != 0 {
		t.Errorf("full-tunnel mark %#x left set after a failed start", m)
	}
	if c.socketMark() != 0 {
		t.Errorf("socket mark %#x left set after a failed start", c.socketMark())
	}
	if c.resolver.Load() != nil {
		t.Error("marked resolver left set after a failed start")
	}
	if c.serverAddrs.Load() != nil {
		t.Error("pinned server addresses left set after a failed start")
	}
}

// syncBuffer is a bytes.Buffer safe to share between the logger's goroutines
// (the in-process server logs too) and the test reading it.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// blackholeListener listens on ip:port with a backlog of zero and fills it, so
// later SYNs are dropped silently: a server address that never answers.
func blackholeListener(t *testing.T, ip string, port int) {
	t.Helper()
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_STREAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = syscall.Close(fd) })
	sa := &syscall.SockaddrInet4{Port: port}
	copy(sa.Addr[:], net.ParseIP(ip).To4())
	if err := syscall.Bind(fd, sa); err != nil {
		t.Skipf("cannot bind %s:%d: %v", ip, port, err)
	}
	if err := syscall.Listen(fd, 0); err != nil {
		t.Fatal(err)
	}
	addr := net.JoinHostPort(ip, strconv.Itoa(port))
	for range 8 {
		if c, err := net.DialTimeout("tcp", addr, 200*time.Millisecond); err == nil {
			t.Cleanup(func() { _ = c.Close() })
		}
	}
	c, err := net.DialTimeout("tcp", addr, 300*time.Millisecond)
	if err == nil {
		_ = c.Close()
		t.Skip("could not fill the accept backlog; no black hole on this kernel")
	}
}

// A first address that silently drops packets must not use up the whole dial
// deadline: the second address still gets its turn.
func TestFullTunnelFallsBackFromABlackHoleAddress(t *testing.T) {
	for _, tc := range []struct{ name, scheme string }{{"rust websocket", "ws"}, {"http2 cleartext", "http"}} {
		t.Run(tc.name, func(t *testing.T) {
			srv := newTestTunServer(t, "rust", "")
			_, portStr, _ := net.SplitHostPort(srv.addr)
			port, _ := strconv.Atoi(portStr)
			blackholeListener(t, "127.0.0.2", port)

			orig := lookupNetIP
			t.Cleanup(func() { lookupNetIP = orig })
			lookupNetIP = func(context.Context, string) ([]netip.Addr, error) {
				return []netip.Addr{netip.MustParseAddr("127.0.0.2"), netip.MustParseAddr("127.0.0.1")}, nil
			}
			f := newFakeHost(t, "127.0.0.1")
			f.nl.routes = routes(map[string]routeInfo{
				"127.0.0.1": {Gateway: netip.MustParseAddr("10.200.0.2"), Link: "eth0"},
				"127.0.0.2": {Gateway: netip.MustParseAddr("10.200.0.2"), Link: "eth0"},
			})
			startFullTunnel(t, f, Config{ServerURL: tc.scheme + "://" + net.JoinHostPort("tun-server.invalid", portStr), PathPrefix: "v1", WebsocketProtocol: "rust"},
				"tun://wst0?route=default&routing=pin")
			waitEcho(t, f.host, "after the black hole")
		})
	}
}
