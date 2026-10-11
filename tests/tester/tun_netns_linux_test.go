//go:build linux

package tester

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// These tests run the real client binary with a real TUN device. That needs
// CAP_NET_ADMIN, which `unshare -rn` grants inside a fresh user + network
// namespace, so they run unprivileged and skip where user namespaces are
// unavailable.
//
// One namespace is not enough. The client routes the target network into the
// TUN, and the server's own dial to that network would take the same route and
// loop back into the tunnel. So the layout is two namespaces joined by a veth
// pair:
//
//	A (client, app)          B (server, echo target)
//	  vA 10.200.0.1/24  <->  vB 10.200.0.2/24
//	  wst0 (the TUN)         lo has 198.51.100.9/32
//	  route 198.51.100.0/24 dev wst0
//
// The app in A connects to 198.51.100.9:7. The kernel sends it into wst0, the
// client carries the packets to the server in B over the veth, and the server
// dials 198.51.100.9:7, which is local to B.
//
// The test binary plays three roles: the parent (TestTunNetns, which starts the
// driver), the driver (runs in A as root of the user namespace) and the echo
// helper (runs in B); the last two are selected by environment. The driver runs
// in its own PID namespace, so when it dies for any reason (panic on timeout,
// SIGKILL) the kernel kills every process it started.
//
// Two extra networks are routed into the tunnel's device: 198.51.100.0/24 is
// allowed by the server rule, 198.51.101.0/24 is routed but refused. A third,
// 198.51.102.0/24, is not routed at all.
const (
	tunDriverEnv = "WST_TUN_NETNS_DRIVER" // transport case name; set only for the driver
	tunBinEnv    = "WST_TUN_NETNS_BIN"    // absolute path of the wstunnel-go binary
	tunEchoEnv   = "WST_TUN_NETNS_ECHO"   // listen address; set only for the echo helper

	tunCaddyEnv = "WST_CADDY_BIN" // a Caddy built with this module (make build-caddy)

	tunNetnsOK = "TUN_NETNS_OK"

	tunServerHost = "10.200.0.2"
	tunServerPort = 18080
	tunTargetIP   = "198.51.100.9"
	tunTargetNet  = "198.51.100.0/24"
	tunTargetPort = 7

	tunRefusedIP  = "198.51.101.9" // routed into the tunnel, refused by the server rule
	tunRefusedNet = "198.51.101.0/24"
	tunUnroutedIP = "198.51.102.9" // not routed into the tunnel
)

// tunUnshareArgs are the unshare flags for the driver: fresh user, network and
// PID namespaces, with /proc remounted so pids and /proc/<pid>/ns/net match the
// namespace, and every process killed when the driver exits.
var tunUnshareArgs = []string{"-rn", "--pid", "--fork", "--mount-proc", "--kill-child"}

var tunNetnsCases = []struct {
	name   string
	scheme string
	flags  []string // passed to both server and client
	attach bool     // pre-create wst0, use configure=false, and run the client without CAP_NET_ADMIN
	caddy  bool     // serve with a Caddy binary that has the wstunnel module instead of wstunnel-go
}{
	{"Go-Go-Tun-WS", "ws", nil, false, false},
	{"Go-Go-Tun-RFC", "ws", []string{"--mode", "ws"}, false, false},
	{"Go-Go-Tun-H2", "http", nil, false, false},
	{"Go-Go-Tun-WT", "wt", nil, false, false},
	{"Go-Go-Tun-Attach", "ws", nil, true, false},
	{"Go-Caddy-Tun-WS", "ws", nil, false, true},
	{"Go-Caddy-Tun-RFC", "ws", []string{"--mode", "ws"}, false, true},
	{"Go-Caddy-Tun-H2", "http", nil, false, true},
}

// caddyBinary finds a Caddy built with the wstunnel module, or returns "".
func caddyBinary() string {
	if p := os.Getenv(tunCaddyEnv); p != "" {
		return p
	}
	if p, err := filepath.Abs("../../pkg/caddy/caddy"); err == nil {
		if st, err := os.Stat(p); err == nil && !st.IsDir() {
			return p
		}
	}
	return ""
}

// caddyfile is the site config for a Caddy server that answers tun sessions on
// the server address, with the same restrictions as the wstunnel-go server and
// tun_allow narrowed to the one network the test may reach.
func caddyfile(rules string, flags []string) string {
	mode := "rust"
	for i, f := range flags {
		if f == "--mode" && i+1 < len(flags) {
			mode = flags[i+1]
		}
	}
	return fmt.Sprintf(`{
	admin off
	auto_https off
	servers {
		protocols h1 h2 h2c
	}
}

http://%s:%d {
	route /v1/* {
		wstunnel {
			prefix v1
			mode %s
			enable_tun
			restrict_config %s
			tun_allow %s
		}
	}
}
`, tunServerHost, tunServerPort, mode, rules, tunTargetNet)
}

func TestTunNetns(t *testing.T) {
	for _, tool := range []string{"unshare", "nsenter", "ip"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s not found in PATH", tool)
		}
	}
	if err := exec.Command("unshare", "-rn", "--pid", "--fork", "--mount-proc", "true").Run(); err != nil {
		t.Skipf("user and network namespaces are unavailable: %v", err)
	}
	if _, err := os.Stat("/dev/net/tun"); err != nil {
		t.Skipf("/dev/net/tun is unavailable: %v", err)
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	bin, err := filepath.Abs(goBinary)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(bin); err != nil {
		t.Fatalf("Go binary not found at %s. Run 'make build' first.", bin)
	}

	for _, tc := range tunNetnsCases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.attach {
				if _, err := exec.LookPath("setpriv"); err != nil {
					t.Skip("setpriv not found in PATH; it is needed to run the client without CAP_NET_ADMIN")
				}
			}
			if tc.caddy && caddyBinary() == "" {
				t.Skip("no Caddy with the wstunnel module: run 'make build-caddy' or set " + tunCaddyEnv)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 150*time.Second)
			defer cancel()
			args := append(append([]string{}, tunUnshareArgs...), exe, "-test.run=^TestTunNetnsDriver$", "-test.v", "-test.timeout=120s")
			cmd := exec.CommandContext(ctx, "unshare", args...)
			cmd.Env = append(os.Environ(), tunDriverEnv+"="+tc.name, tunBinEnv+"="+bin, tunCaddyEnv+"="+caddyBinary())
			out, err := cmd.CombinedOutput()
			if err != nil || !strings.Contains(string(out), tunNetnsOK) {
				t.Fatalf("namespace driver failed (err=%v):\n%s", err, out)
			}
		})
	}
}

// TestTunNetnsDriver is the body of one case. It only runs when re-executed by
// TestTunNetns, as root of a fresh user and network namespace (A).
func TestTunNetnsDriver(t *testing.T) {
	name := os.Getenv(tunDriverEnv)
	if name == "" {
		t.Skip("runs only inside the namespace driver process")
	}
	bin := os.Getenv(tunBinEnv)
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	var scheme string
	var flags []string
	var attach, viaCaddy bool
	for _, tc := range tunNetnsCases {
		if tc.name == name {
			scheme, flags, attach, viaCaddy = tc.scheme, tc.flags, tc.attach, tc.caddy
		}
	}
	if scheme == "" {
		t.Fatalf("unknown case %q", name)
	}

	run := func(args ...string) {
		t.Helper()
		if out, err := exec.Command(args[0], args[1:]...).CombinedOutput(); err != nil {
			t.Fatalf("%s: %v\n%s", strings.Join(args, " "), err, out)
		}
	}

	run("ip", "link", "set", "lo", "up")

	// Namespace B is held open by a sleeping process.
	holder := exec.Command("unshare", "-n", "sleep", "300")
	if err := holder.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = holder.Process.Kill()
		_ = holder.Wait()
	}()
	pid := strconv.Itoa(holder.Process.Pid)
	mine, err := os.Readlink("/proc/self/ns/net")
	if err != nil {
		t.Fatal(err)
	}
	if err := waitUntil(5*time.Second, func() bool {
		theirs, err := os.Readlink("/proc/" + pid + "/ns/net")
		return err == nil && theirs != mine
	}); err != nil {
		t.Fatalf("namespace B did not appear: %v", err)
	}
	inB := func(args ...string) []string {
		return append([]string{"nsenter", "-t", pid, "-n", "--"}, args...)
	}

	run("ip", "link", "add", "vA", "type", "veth", "peer", "name", "vB")
	run("ip", "link", "set", "vB", "netns", pid)
	run("ip", "addr", "add", "10.200.0.1/24", "dev", "vA")
	run("ip", "link", "set", "vA", "up")
	run(inB("ip", "link", "set", "lo", "up")...)
	run(inB("ip", "addr", "add", tunServerHost+"/24", "dev", "vB")...)
	run(inB("ip", "link", "set", "vB", "up")...)
	run(inB("ip", "addr", "add", tunTargetIP+"/32", "dev", "lo")...)
	run(inB("ip", "addr", "add", tunRefusedIP+"/32", "dev", "lo")...)

	// The server admits tun sessions and flows to the target network only.
	rules := filepath.Join(t.TempDir(), "rules.yaml")
	if err := os.WriteFile(rules, []byte(fmt.Sprintf(`restrictions:
  - name: tun-netns
    match:
      - Any
    allow:
      - !Tunnel
        protocol: [Tun]
      - !Tunnel
        protocol: [Tcp, Udp]
        cidr: [%s]
`, tunTargetNet)), 0o600); err != nil {
		t.Fatal(err)
	}

	serverURL := fmt.Sprintf("%s://%s:%d", scheme, tunServerHost, tunServerPort)
	var serverArgs []string
	var serverEnv []string
	if viaCaddy {
		cfgDir := t.TempDir()
		cfgPath := filepath.Join(cfgDir, "Caddyfile")
		if err := os.WriteFile(cfgPath, []byte(caddyfile(rules, flags)), 0o600); err != nil {
			t.Fatal(err)
		}
		serverArgs = []string{"nsenter", "-t", pid, "-n", "--", os.Getenv(tunCaddyEnv), "run", "--config", cfgPath, "--adapter", "caddyfile"}
		// Keep Caddy's storage out of the real home directory.
		serverEnv = append(os.Environ(), "HOME="+cfgDir, "XDG_DATA_HOME="+cfgDir+"/data", "XDG_CONFIG_HOME="+cfgDir+"/config")
	} else {
		serverArgs = append([]string{"nsenter", "-t", pid, "-n", "--", bin, "--log-lvl", "DEBUG",
			"server", "--http-upgrade-path-prefix", "v1", "--enable-tun", "--restrict-config", rules}, flags...)
		serverArgs = append(serverArgs, serverURL)
	}
	srv, err := startProcess("Server-"+name, serverArgs[0], serverArgs[1:], serverEnv)
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Stop()

	echo, err := startProcess("Echo-"+name, "nsenter", []string{"-t", pid, "-n", "--", exe, "-test.run=^TestTunNetnsHelperEcho$"},
		append(os.Environ(), tunEchoEnv+fmt.Sprintf("=%s:%d,%s:%d", tunTargetIP, tunTargetPort, tunRefusedIP, tunTargetPort)))
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Stop()

	if err := waitForPort(tunServerHost, tunServerPort, 10*time.Second); err != nil {
		t.Fatalf("server in namespace B did not start: %v", err)
	}

	tunArg := fmt.Sprintf("tun://wst0?addr=198.18.0.1/32&route=%s&route=%s", tunTargetNet, tunRefusedNet)
	if attach {
		// An administrator pre-creates the device and owns its configuration; the
		// client only attaches to it and must not change anything.
		run("ip", "tuntap", "add", "dev", "wst0", "mode", "tun")
		run("ip", "link", "set", "wst0", "mtu", "1400")
		run("ip", "addr", "add", "198.18.0.1/32", "dev", "wst0")
		run("ip", "link", "set", "wst0", "up")
		run("ip", "route", "add", tunTargetNet, "dev", "wst0")
		run("ip", "route", "add", tunRefusedNet, "dev", "wst0")
		tunArg = "tun://wst0?configure=false"
	}
	clientArgs := append([]string{"--log-lvl", "DEBUG", "client", "--http-upgrade-path-prefix", "v1"}, flags...)
	clientArgs = append(clientArgs, "-L", tunArg, serverURL)
	clientBin := bin
	if attach {
		// Attaching to a persistent device must work without CAP_NET_ADMIN: that
		// is the whole point of configure=false. Run the client with the
		// capability removed, so any attempt to change the device fails.
		clientArgs = append([]string{"--bounding-set=-net_admin", "--inh-caps=-net_admin", bin}, clientArgs...)
		clientBin = "setpriv"
	}
	cli, err := startProcess("Client-"+name, clientBin, clientArgs, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer cli.Stop()

	if !attach {
		if err := waitUntil(10*time.Second, func() bool {
			out, err := exec.Command("ip", "route", "show", tunTargetNet).CombinedOutput()
			return err == nil && strings.Contains(string(out), "wst0")
		}); err != nil {
			t.Fatalf("the client did not create wst0 with its route: %v", err)
		}
	}

	// The app dials the target; the kernel routes it into wst0.
	target := net.JoinHostPort(tunTargetIP, strconv.Itoa(tunTargetPort))
	var tcpErr error
	if err := waitUntil(15*time.Second, func() bool {
		tcpErr = echoTCP(target, "tcp through "+name)
		return tcpErr == nil
	}); err != nil {
		t.Fatalf("TCP through the tunnel: %v (last error: %v)", err, tcpErr)
	}
	if err := echoUDP(target, "udp through "+name); err != nil {
		t.Fatalf("UDP through the tunnel: %v", err)
	}

	// Routed into the tunnel but refused by the server rule. The echo target at
	// this address is alive, so a connection reset can only come from the
	// server refusing the flow.
	refused := net.JoinHostPort(tunRefusedIP, strconv.Itoa(tunTargetPort))
	if conn, err := net.DialTimeout("tcp", refused, 3*time.Second); err == nil {
		_ = conn.Close()
		t.Fatal("a flow the server rule does not allow was accepted")
	} else if !errors.Is(err, syscall.ECONNREFUSED) {
		t.Fatalf("dial to routed but refused %s: %v, want ECONNREFUSED", refused, err)
	}

	// Not routed into the tunnel at all: the kernel has no route.
	unrouted := net.JoinHostPort(tunUnroutedIP, strconv.Itoa(tunTargetPort))
	if conn, err := net.DialTimeout("tcp", unrouted, 3*time.Second); err == nil {
		_ = conn.Close()
		t.Fatal("a destination outside the routed networks was reachable")
	} else if !errors.Is(err, syscall.ENETUNREACH) {
		t.Fatalf("dial to unrouted %s: %v, want ENETUNREACH", unrouted, err)
	}

	fmt.Println(tunNetnsOK)
}

// TestTunNetnsHelperEcho is a TCP and UDP echo server for namespace B. The
// environment holds a comma-separated list of addresses.
func TestTunNetnsHelperEcho(t *testing.T) {
	env := os.Getenv(tunEchoEnv)
	if env == "" {
		t.Skip("runs only as the namespace echo helper")
	}
	errc := make(chan error, 1)
	for _, addr := range strings.Split(env, ",") {
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			t.Fatal(err)
		}
		pc, err := net.ListenPacket("udp", addr)
		if err != nil {
			t.Fatal(err)
		}
		go func() {
			buf := make([]byte, 65535)
			for {
				n, from, err := pc.ReadFrom(buf)
				if err != nil {
					return
				}
				_, _ = pc.WriteTo(buf[:n], from)
			}
		}()
		go func() {
			for {
				c, err := ln.Accept()
				if err != nil {
					errc <- err
					return
				}
				go func() {
					defer func() { _ = c.Close() }()
					_, _ = io.Copy(c, c)
				}()
			}
		}()
	}
	t.Fatal(<-errc)
}

func waitUntil(timeout time.Duration, cond func() bool) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	return fmt.Errorf("condition not met within %v", timeout)
}

func echoTCP(addr, msg string) error {
	c, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		return err
	}
	defer func() { _ = c.Close() }()
	_ = c.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := c.Write([]byte(msg)); err != nil {
		return err
	}
	buf := make([]byte, len(msg))
	if _, err := io.ReadFull(c, buf); err != nil {
		return err
	}
	if string(buf) != msg {
		return fmt.Errorf("echo = %q, want %q", buf, msg)
	}
	return nil
}

func echoUDP(addr, msg string) error {
	c, err := net.Dial("udp", addr)
	if err != nil {
		return err
	}
	defer func() { _ = c.Close() }()
	// UDP has no handshake, so retry until the first datagram gets through.
	buf := make([]byte, 2048)
	for i := 0; i < 5; i++ {
		if _, err := c.Write([]byte(msg)); err != nil {
			return err
		}
		_ = c.SetReadDeadline(time.Now().Add(time.Second))
		n, err := c.Read(buf)
		if err == nil {
			if string(buf[:n]) != msg {
				return fmt.Errorf("echo = %q, want %q", buf[:n], msg)
			}
			return nil
		}
	}
	return fmt.Errorf("no UDP echo after 5 attempts")
}

// ---------------------------------------------------------------------------
// Full tunnel (route=default)
//
// Three namespaces, so the server is reached the way a real one is: through
// the default route, which the full tunnel then replaces.
//
//	A (client, app)               B (gateway, server)            C (target)
//	  vAB 10.200.0.1/24  <------>   vBA 10.200.0.2/24
//	  default via 10.200.0.2        lo 192.0.2.10/32 (server)    lo 203.0.113.50/32
//	  wst0 (the TUN)                vBC 10.201.0.1/24  <------>  vCB 10.201.0.2/24
//	                                route 203.0.113.50/32 via C  default via B
//
// B does not forward, so A cannot reach 203.0.113.50 except through the
// tunnel. There is deliberately no explicit route to the server in A: reaching
// it through the default route is what makes strict rp_filter break the fwmark
// mode (the server's replies fail the reverse-path check), and what a host
// route "hides" if one is added.
//
// A packet sniffer in B watches vBA for anything addressed to the target: a
// packet seen there left A's default route instead of the tunnel.
// ---------------------------------------------------------------------------
const (
	fullDriverEnv = "WST_TUN_NETNS_FULL"  // case name; set only for the full-tunnel driver
	fullSniffEnv  = "WST_TUN_NETNS_SNIFF" // interface to sniff; set only for the sniffer helper

	fullServerIP   = "192.0.2.10"
	fullTargetIP   = "203.0.113.50"
	fullTargetNet  = "203.0.113.0/24"
	fullDefaultMrk = "0x7774"
)

type fullCase struct {
	name     string
	routing  string // routing= value; "" omits it
	rpFilter int    // rp_filter set on all interfaces of A before the client starts
	scenario string
	wantMode string // routing mode the client must log
}

var fullCases = []fullCase{
	{"Go-Go-Tun-Full-Fwmark", "fwmark", 2, "basic", "fwmark"},
	{"Go-Go-Tun-Full-Fwmark-RPOff", "fwmark", 0, "basic", "fwmark"},
	{"Go-Go-Tun-Full-Pin", "pin", 2, "basic", "pin"},
	{"Go-Go-Tun-Full-Pin-StrictRP", "pin", 1, "basic", "pin"},
	{"Go-Go-Tun-Full-Auto-StrictRP", "auto", 1, "basic", "pin"},
	{"Go-Go-Tun-Full-Auto-LooseRP", "", 2, "basic", "fwmark"},
	{"Go-Go-Tun-Full-Fwmark-StrictRP-Refused", "fwmark", 1, "refuse", ""},
	{"Go-Go-Tun-Full-Cleanup-Fwmark", "fwmark", 2, "cleanup", "fwmark"},
	{"Go-Go-Tun-Full-Cleanup-Pin", "pin", 2, "cleanup", "pin"},
	{"Go-Go-Tun-Full-Crash-Fwmark", "fwmark", 2, "crash", "fwmark"},
	{"Go-Go-Tun-Full-Reconnect-Fwmark", "fwmark", 2, "reconnect", "fwmark"},
	{"Go-Go-Tun-Full-Reconnect-Pin", "pin", 2, "reconnect", "pin"},
}

func TestTunNetnsFull(t *testing.T) {
	for _, tool := range []string{"unshare", "nsenter", "ip"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s not found in PATH", tool)
		}
	}
	if err := exec.Command("unshare", "-rn", "--pid", "--fork", "--mount-proc", "true").Run(); err != nil {
		t.Skipf("user and network namespaces are unavailable: %v", err)
	}
	if _, err := os.Stat("/dev/net/tun"); err != nil {
		t.Skipf("/dev/net/tun is unavailable: %v", err)
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	bin, err := filepath.Abs(goBinary)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(bin); err != nil {
		t.Fatalf("Go binary not found at %s. Run 'make build' first.", bin)
	}
	for _, tc := range fullCases {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 170*time.Second)
			defer cancel()
			args := append(append([]string{}, tunUnshareArgs...), exe, "-test.run=^TestTunNetnsFullDriver$", "-test.v", "-test.timeout=150s")
			cmd := exec.CommandContext(ctx, "unshare", args...)
			cmd.Env = append(os.Environ(), fullDriverEnv+"="+tc.name, tunBinEnv+"="+bin)
			out, err := cmd.CombinedOutput()
			if err != nil || !strings.Contains(string(out), tunNetnsOK) {
				t.Fatalf("namespace driver failed (err=%v):\n%s", err, out)
			}
		})
	}
}

// capturedProc is a child process whose output is kept for assertions.
type capturedProc struct {
	cmd  *exec.Cmd
	mu   sync.Mutex
	out  strings.Builder
	done chan struct{}
	err  error
}

func startCaptured(name string, env []string, binary string, args ...string) (*capturedProc, error) {
	cmd := exec.Command(binary, args...)
	cmd.Env = env
	p := &capturedProc{cmd: cmd, done: make(chan struct{})}
	w := &lockedWriter{p: p, prefix: "[" + name + "] "}
	cmd.Stdout, cmd.Stderr = w, w
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	go func() {
		p.err = cmd.Wait()
		close(p.done)
	}()
	return p, nil
}

type lockedWriter struct {
	p      *capturedProc
	prefix string
}

func (w *lockedWriter) Write(b []byte) (int, error) {
	w.p.mu.Lock()
	w.p.out.Write(b)
	w.p.mu.Unlock()
	_, _ = os.Stdout.WriteString(w.prefix + string(b))
	return len(b), nil
}

func (p *capturedProc) output() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.out.String()
}

// terminate sends sig and waits for the process to exit.
func (p *capturedProc) terminate(sig os.Signal, within time.Duration) error {
	_ = p.cmd.Process.Signal(sig)
	select {
	case <-p.done:
		return p.err
	case <-time.After(within):
		_ = p.cmd.Process.Kill()
		<-p.done
		return fmt.Errorf("did not exit within %v after %v", within, sig)
	}
}

func (p *capturedProc) kill() {
	_ = p.cmd.Process.Kill()
	<-p.done
}

func (p *capturedProc) exited() bool {
	select {
	case <-p.done:
		return true
	default:
		return false
	}
}

func TestTunNetnsFullDriver(t *testing.T) {
	name := os.Getenv(fullDriverEnv)
	if name == "" {
		t.Skip("runs only inside the full-tunnel namespace driver process")
	}
	bin := os.Getenv(tunBinEnv)
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	var tc fullCase
	for _, c := range fullCases {
		if c.name == name {
			tc = c
		}
	}
	if tc.name == "" {
		t.Fatalf("unknown case %q", name)
	}

	run := func(args ...string) string {
		t.Helper()
		out, err := exec.Command(args[0], args[1:]...).CombinedOutput()
		if err != nil {
			t.Fatalf("%s: %v\n%s", strings.Join(args, " "), err, out)
		}
		return string(out)
	}
	try := func(args ...string) string {
		out, _ := exec.Command(args[0], args[1:]...).CombinedOutput()
		return string(out)
	}

	run("ip", "link", "set", "lo", "up")

	// Namespaces B and C are held open by sleeping processes.
	hold := func(label string) string {
		h := exec.Command("unshare", "-n", "sleep", "300")
		if err := h.Start(); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = h.Process.Kill(); _ = h.Wait() })
		pid := strconv.Itoa(h.Process.Pid)
		mine, _ := os.Readlink("/proc/self/ns/net")
		if err := waitUntil(5*time.Second, func() bool {
			theirs, err := os.Readlink("/proc/" + pid + "/ns/net")
			return err == nil && theirs != mine
		}); err != nil {
			t.Fatalf("namespace %s did not appear: %v", label, err)
		}
		return pid
	}
	pidB, pidC := hold("B"), hold("C")
	inB := func(args ...string) []string { return append([]string{"nsenter", "-t", pidB, "-n", "--"}, args...) }
	inC := func(args ...string) []string { return append([]string{"nsenter", "-t", pidC, "-n", "--"}, args...) }

	// A <-> B
	run("ip", "link", "add", "vAB", "type", "veth", "peer", "name", "vBA")
	run("ip", "link", "set", "vBA", "netns", pidB)
	run("ip", "addr", "add", "10.200.0.1/24", "dev", "vAB")
	run("ip", "link", "set", "vAB", "up")
	run(inB("ip", "link", "set", "lo", "up")...)
	run(inB("ip", "addr", "add", "10.200.0.2/24", "dev", "vBA")...)
	run(inB("ip", "link", "set", "vBA", "up")...)
	run(inB("ip", "addr", "add", fullServerIP+"/32", "dev", "lo")...)
	// B <-> C
	run(inB("ip", "link", "add", "vBC", "type", "veth", "peer", "name", "vCB")...)
	run(inB("ip", "link", "set", "vCB", "netns", pidC)...)
	run(inB("ip", "addr", "add", "10.201.0.1/24", "dev", "vBC")...)
	run(inB("ip", "link", "set", "vBC", "up")...)
	run(inB("ip", "route", "add", fullTargetIP+"/32", "via", "10.201.0.2")...)
	run(inC("ip", "link", "set", "lo", "up")...)
	run(inC("ip", "addr", "add", "10.201.0.2/24", "dev", "vCB")...)
	run(inC("ip", "link", "set", "vCB", "up")...)
	run(inC("ip", "addr", "add", fullTargetIP+"/32", "dev", "lo")...)
	run(inC("ip", "route", "add", "default", "via", "10.201.0.1")...)
	// A reaches the server address through B, as it would reach a server on the
	// internet. No host route to the server.
	run("ip", "route", "add", "default", "via", "10.200.0.2")

	for _, scope := range []string{"all", "default", "vAB"} {
		if err := os.WriteFile("/proc/sys/net/ipv4/conf/"+scope+"/rp_filter", []byte(strconv.Itoa(tc.rpFilter)), 0o644); err != nil {
			t.Fatalf("set rp_filter on %s: %v", scope, err)
		}
	}

	rules := filepath.Join(t.TempDir(), "rules.yaml")
	if err := os.WriteFile(rules, []byte(fmt.Sprintf(`restrictions:
  - name: tun-netns-full
    match:
      - Any
    allow:
      - !Tunnel
        protocol: [Tun]
      - !Tunnel
        protocol: [Tcp, Udp]
        cidr: [%s]
`, fullTargetNet)), 0o600); err != nil {
		t.Fatal(err)
	}
	serverURL := fmt.Sprintf("ws://%s:%d", fullServerIP, tunServerPort)
	startServer := func() *capturedProc {
		t.Helper()
		p, err := startCaptured("server", nil, "nsenter", inB(bin, "--log-lvl", "INFO", "server", "--http-upgrade-path-prefix", "v1",
			"--enable-tun", "--restrict-config", rules, serverURL)[1:]...)
		if err != nil {
			t.Fatal(err)
		}
		// Ask B itself: with the full tunnel up, A's own dials go into the tunnel.
		if err := waitUntil(10*time.Second, func() bool {
			return strings.Contains(try(inB("ss", "-ltn", "sport", "=", ":"+strconv.Itoa(tunServerPort))...), fullServerIP+":"+strconv.Itoa(tunServerPort))
		}); err != nil {
			p.kill()
			t.Fatalf("server in namespace B did not start: %v\n%s", err, p.output())
		}
		return p
	}

	echo, err := startProcess("Echo-"+name, "nsenter", inC(exe, "-test.run=^TestTunNetnsHelperEcho$")[1:],
		append(os.Environ(), tunEchoEnv+fmt.Sprintf("=%s:%d", fullTargetIP, tunTargetPort)))
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Stop()

	// The sniffer in B reports anything addressed to the target on the A-B link.
	sniff, err := startCaptured("sniffer", append(os.Environ(), fullSniffEnv+"=1"), "nsenter", inB(exe, "-test.run=^TestTunNetnsHelperSniff$", "-test.v")[1:]...)
	if err != nil {
		t.Fatal(err)
	}
	defer sniff.kill()
	if err := waitUntil(10*time.Second, func() bool { return strings.Contains(sniff.output(), "SNIFFER-READY") }); err != nil {
		t.Fatalf("the sniffer in namespace B did not start:\n%s", sniff.output())
	}

	srv := startServer()
	defer func() { srv.kill() }()

	target := net.JoinHostPort(fullTargetIP, strconv.Itoa(tunTargetPort))

	// Sanity: B does not forward, so without the tunnel the target is unreachable.
	if conn, err := net.DialTimeout("tcp", target, 2*time.Second); err == nil {
		_ = conn.Close()
		t.Fatal("the target is reachable without the tunnel; the topology is wrong")
	}
	// ...and the sniffer must see those packets, or "no leak" below means nothing.
	if err := waitUntil(3*time.Second, func() bool { return strings.Contains(sniff.output(), "LEAK ") }); err != nil {
		t.Fatalf("the sniffer in B did not see packets sent out of A's default route:\n%s", sniff.output())
	}
	// The sanity dial deliberately sent packets out of the default route (and
	// its SYN retransmits trail in); only packets after this point are leaks.
	time.Sleep(time.Second)
	leakBase := strings.Count(sniff.output(), "LEAK ")
	resetLeaks := func() {
		time.Sleep(500 * time.Millisecond)
		leakBase = strings.Count(sniff.output(), "LEAK ")
	}

	tunArg := "tun://wst0?route=default"
	if tc.routing != "" {
		tunArg += "&routing=" + tc.routing
	}
	startClient := func() *capturedProc {
		t.Helper()
		p, err := startCaptured("client", nil, bin, "--log-lvl", "INFO", "client", "--http-upgrade-path-prefix", "v1", "-L", tunArg, serverURL)
		if err != nil {
			t.Fatal(err)
		}
		// Until the routing is installed the app's packets take the normal
		// default route, as they did before the client started; that is not a
		// leak. Wait for the tunnel to own the route, then start counting.
		if err := waitUntil(10*time.Second, func() bool {
			return p.exited() || strings.Contains(try("ip", "route", "get", fullTargetIP), "wst0")
		}); err != nil || p.exited() {
			if !strings.Contains(tc.scenario, "refuse") {
				t.Fatalf("the full tunnel was not installed (err=%v):\n%s", err, p.output())
			}
		}
		resetLeaks()
		return p
	}
	waitEchoOK := func(label string, within time.Duration) {
		t.Helper()
		var last error
		if err := waitUntil(within, func() bool {
			last = echoTCP(target, label)
			return last == nil
		}); err != nil {
			t.Fatalf("%s: no TCP echo through the full tunnel: %v", label, last)
		}
	}
	rulesText := func() string {
		return try("ip", "rule", "show") + try("ip", "-6", "rule", "show")
	}
	countRules := func(sub string) int { return strings.Count(rulesText(), sub) }
	// A table with no routes does not exist; the kernel's complaint means empty.
	table := func() string {
		var keep []string
		for _, line := range strings.Split(try("ip", "route", "show", "table", "30580")+try("ip", "-6", "route", "show", "table", "30580"), "\n") {
			if l := strings.TrimSpace(line); l != "" && !strings.HasPrefix(l, "Error:") && l != "Dump terminated" {
				keep = append(keep, l)
			}
		}
		return strings.Join(keep, "\n")
	}
	leaks := func() int { return strings.Count(sniff.output(), "LEAK ") - leakBase }

	switch tc.scenario {
	case "refuse":
		cli := startClient()
		select {
		case <-cli.done:
		case <-time.After(15 * time.Second):
			cli.kill()
			t.Fatalf("the client kept running; it must refuse to start:\n%s", cli.output())
		}
		out := cli.output()
		if cli.err == nil {
			t.Fatalf("the client exited 0; want a refusal:\n%s", out)
		}
		for _, want := range []string{"rp_filter=1", "routing=pin"} {
			if !strings.Contains(out, want) {
				t.Errorf("refusal message lacks %q:\n%s", want, out)
			}
		}
		if got := try("ip", "link", "show", "wst0"); strings.Contains(got, "wst0:") {
			t.Errorf("a device was created before the refusal:\n%s", got)
		}
		if n := countRules("32760") + countRules("32761"); n != 0 {
			t.Errorf("%d rules installed before the refusal:\n%s", n, rulesText())
		}

	case "basic":
		cli := startClient()
		defer cli.kill()
		waitEchoOK("full tunnel "+name, 20*time.Second)
		if err := echoUDP(target, "udp full tunnel"); err != nil {
			t.Errorf("UDP through the full tunnel: %v", err)
		}
		if !strings.Contains(cli.output(), "mode="+tc.wantMode) {
			t.Errorf("the client did not log routing mode %s:\n%s", tc.wantMode, cli.output())
		}
		// The default route carries the app's traffic into the device.
		if got := try("ip", "route", "get", fullTargetIP); !strings.Contains(got, "wst0") {
			t.Errorf("ip route get %s = %q, want it through wst0", fullTargetIP, got)
		}
		// The session itself must keep working after it has been idle.
		time.Sleep(3 * time.Second)
		waitEchoOK("after idle "+name, 10*time.Second)
		checkInstalled(t, tc.wantMode, rulesText(), table(), try("ip", "route", "show"))

	case "cleanup":
		cli := startClient()
		defer cli.kill()
		waitEchoOK("before SIGTERM", 20*time.Second)
		checkInstalled(t, tc.wantMode, rulesText(), table(), try("ip", "route", "show"))
		if n := leaks(); n != 0 {
			t.Fatalf("%d packets leaked while the tunnel was up:\n%s", n, sniff.output())
		}
		if err := cli.terminate(syscall.SIGTERM, 10*time.Second); err != nil {
			t.Fatalf("client after SIGTERM: %v\n%s", err, cli.output())
		}
		checkClean(t, rulesText(), table(), try("ip", "route", "show"), try("ip", "-6", "route", "show"))
		// The host is back to its normal routing: the target is unreachable again
		// and the server address still reachable directly.
		if err := echoTCP(target, "x"); err == nil {
			t.Error("the target is reachable after the client exited")
		}
		if err := waitForPort(fullServerIP, tunServerPort, 3*time.Second); err != nil {
			t.Errorf("the server is unreachable after cleanup: %v", err)
		}

	case "crash":
		cli := startClient()
		waitEchoOK("before SIGKILL", 20*time.Second)
		cli.kill()
		// The device is gone with the process, the rules are not.
		if n := countRules("32761"); n == 0 {
			t.Fatalf("expected stale rules after SIGKILL, found none:\n%s", rulesText())
		}
		if got := try("ip", "link", "show", "wst0"); strings.Contains(got, "wst0:") {
			t.Fatalf("wst0 survived SIGKILL:\n%s", got)
		}
		// A stale rule must not black-hole the host: its table is empty, so lookups
		// fall through to main and the server stays reachable.
		if err := waitForPort(fullServerIP, tunServerPort, 3*time.Second); err != nil {
			t.Fatalf("stale rules cut the host off from the server: %v", err)
		}
		cli = startClient()
		defer cli.kill()
		waitEchoOK("after restart", 20*time.Second)
		for _, sub := range []string{"32760:", "32761:"} {
			// one rule per priority and family, not an accumulation
			if n := countRules(sub); n != 2 {
				t.Errorf("%d rules at priority %s after the restart, want 2 (IPv4 and IPv6):\n%s", n, sub, rulesText())
			}
		}
		if !strings.Contains(cli.output(), "stale rule") {
			t.Errorf("the client did not report removing the stale rules:\n%s", cli.output())
		}
		if err := cli.terminate(syscall.SIGTERM, 10*time.Second); err != nil {
			t.Fatalf("client after SIGTERM: %v", err)
		}
		checkClean(t, rulesText(), table(), try("ip", "route", "show"), try("ip", "-6", "route", "show"))

	case "reconnect":
		cli := startClient()
		defer cli.kill()
		waitEchoOK("before outage", 20*time.Second)

		srv.kill()
		// While the server is down the routed traffic must be dropped, not sent
		// out of the default route.
		for i := 0; i < 3; i++ {
			if err := echoTCP(target, "during outage"); err == nil {
				t.Fatal("traffic flowed while the server was down")
			}
		}
		if n := leaks(); n != 0 {
			t.Fatalf("%d packets for %s left A through its default route during the outage:\n%s", n, fullTargetIP, sniff.output())
		}
		if cli.exited() {
			t.Fatalf("the client exited during the outage:\n%s", cli.output())
		}

		srv = startServer()
		waitEchoOK("after the server came back", 45*time.Second)
		if n := leaks(); n != 0 {
			t.Fatalf("%d packets leaked during the test:\n%s", n, sniff.output())
		}
		checkInstalled(t, tc.wantMode, rulesText(), table(), try("ip", "route", "show"))
	}

	if tc.scenario == "basic" || tc.scenario == "reconnect" {
		if n := leaks(); n != 0 {
			t.Fatalf("%d packets for %s left A through its default route:\n%s", n, fullTargetIP, sniff.output())
		}
	}
	fmt.Println(tunNetnsOK)
}

// checkInstalled asserts the routing state of a running full tunnel.
func checkInstalled(t *testing.T, mode, rules, table, routes string) {
	t.Helper()
	switch mode {
	case "fwmark":
		for _, want := range []string{"32760:", "32761:", "not from all fwmark " + fullDefaultMrk} {
			if !strings.Contains(rules, want) {
				t.Errorf("fwmark mode: rules lack %q:\n%s", want, rules)
			}
		}
		if !strings.Contains(table, "default dev wst0") {
			t.Errorf("fwmark mode: table 30580 = %q, want a default route via wst0", table)
		}
	case "pin":
		for _, want := range []string{"0.0.0.0/1 dev wst0", "128.0.0.0/1 dev wst0", fullServerIP + " via 10.200.0.2 dev vAB"} {
			if !strings.Contains(routes, want) {
				t.Errorf("pin mode: routes lack %q:\n%s", want, routes)
			}
		}
		if strings.Contains(rules, "32761:") {
			t.Errorf("pin mode installed policy rules:\n%s", rules)
		}
	}
}

// checkClean asserts a stopped full tunnel left nothing behind.
func checkClean(t *testing.T, rules, table, routes, routes6 string) {
	t.Helper()
	for _, bad := range []string{"32760:", "32761:", "fwmark"} {
		if strings.Contains(rules, bad) {
			t.Errorf("rules left behind (%q):\n%s", bad, rules)
		}
	}
	if strings.TrimSpace(table) != "" {
		t.Errorf("table 30580 not empty:\n%s", table)
	}
	for _, bad := range []string{"wst0", "0.0.0.0/1", "128.0.0.0/1", fullServerIP} {
		if strings.Contains(routes, bad) {
			t.Errorf("route left behind (%q):\n%s", bad, routes)
		}
	}
	for _, bad := range []string{"wst0", "::/1", "8000::/1"} {
		if strings.Contains(routes6, bad) {
			t.Errorf("IPv6 route left behind (%q):\n%s", bad, routes6)
		}
	}
}

// TestTunNetnsHelperSniff runs in namespace B and prints a line for every IPv4
// packet addressed to the target that arrives on the A-B link.
func TestTunNetnsHelperSniff(t *testing.T) {
	if os.Getenv(fullSniffEnv) == "" {
		t.Skip("runs only as the namespace sniffer helper")
	}
	ifi, err := net.InterfaceByName("vBA")
	if err != nil {
		t.Fatal(err)
	}
	proto := uint16(syscall.ETH_P_IP)
	be := (proto << 8) | (proto >> 8) // htons
	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(be))
	if err != nil {
		t.Fatal(err)
	}
	if err := syscall.Bind(fd, &syscall.SockaddrLinklayer{Protocol: be, Ifindex: ifi.Index}); err != nil {
		t.Fatal(err)
	}
	target := net.ParseIP(fullTargetIP).To4()
	fmt.Println("SNIFFER-READY")
	buf := make([]byte, 65536)
	for {
		n, from, err := syscall.Recvfrom(fd, buf, 0)
		if err != nil {
			t.Fatal(err)
		}
		if sll, ok := from.(*syscall.SockaddrLinklayer); ok && sll.Pkttype == syscall.PACKET_OUTGOING {
			continue
		}
		if n >= 14+20 && net.IP(buf[14+16:14+20]).Equal(target) {
			fmt.Printf("LEAK dst=%s len=%d\n", target, n)
		}
	}
}
