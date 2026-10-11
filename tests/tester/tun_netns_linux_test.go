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
