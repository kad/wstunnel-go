//go:build linux

package tester

import (
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
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
// The test binary re-executes itself in three roles, selected by environment:
// the driver (runs in A as root of the user namespace), and the echo helper
// (runs in B).
const (
	tunDriverEnv = "WST_TUN_NETNS_DRIVER" // transport case name; set only for the driver
	tunBinEnv    = "WST_TUN_NETNS_BIN"    // absolute path of the wstunnel-go binary
	tunEchoEnv   = "WST_TUN_NETNS_ECHO"   // listen address; set only for the echo helper

	tunNetnsOK = "TUN_NETNS_OK"

	tunServerHost = "10.200.0.2"
	tunServerPort = 18080
	tunTargetIP   = "198.51.100.9"
	tunTargetNet  = "198.51.100.0/24"
	tunTargetPort = 7
)

var tunNetnsCases = []struct {
	name   string
	scheme string
	flags  []string // passed to both server and client
	attach bool     // pre-create wst0, use configure=false, and run the client without CAP_NET_ADMIN
}{
	{"Go-Go-Tun-WS", "ws", nil, false},
	{"Go-Go-Tun-RFC", "ws", []string{"--mode", "ws"}, false},
	{"Go-Go-Tun-H2", "http", nil, false},
	{"Go-Go-Tun-WT", "wt", nil, false},
	{"Go-Go-Tun-Attach", "ws", nil, true},
}

func TestTunNetns(t *testing.T) {
	for _, tool := range []string{"unshare", "nsenter", "ip"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s not found in PATH", tool)
		}
	}
	if err := exec.Command("unshare", "-rn", "true").Run(); err != nil {
		t.Skipf("user and network namespaces are unavailable: %v", err)
	}
	if _, err := os.Stat("/dev/net/tun"); err != nil {
		t.Skipf("/dev/net/tun is unavailable: %v", err)
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
			cmd := exec.Command("unshare", "-rn", os.Args[0], "-test.run=^TestTunNetnsDriver$", "-test.v", "-test.timeout=120s")
			cmd.Env = append(os.Environ(), tunDriverEnv+"="+tc.name, tunBinEnv+"="+bin)
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
	var scheme string
	var flags []string
	var attach bool
	for _, tc := range tunNetnsCases {
		if tc.name == name {
			scheme, flags, attach = tc.scheme, tc.flags, tc.attach
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
	mine, _ := os.Readlink("/proc/self/ns/net")
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
	serverArgs := append([]string{"nsenter", "-t", pid, "-n", "--", bin, "--log-lvl", "DEBUG",
		"server", "--http-upgrade-path-prefix", "v1", "--enable-tun", "--restrict-config", rules}, flags...)
	serverArgs = append(serverArgs, serverURL)
	srv, err := startProcess("Server-"+name, serverArgs[0], serverArgs[1:], nil)
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Stop()

	echo, err := startProcess("Echo-"+name, "nsenter", []string{"-t", pid, "-n", "--", os.Args[0], "-test.run=^TestTunNetnsHelperEcho$"},
		append(os.Environ(), tunEchoEnv+fmt.Sprintf("=%s:%d", tunTargetIP, tunTargetPort)))
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Stop()

	if err := waitForPort(tunServerHost, tunServerPort, 10*time.Second); err != nil {
		t.Fatalf("server in namespace B did not start: %v", err)
	}

	tunArg := fmt.Sprintf("tun://wst0?addr=198.18.0.1/32&route=%s", tunTargetNet)
	if attach {
		// An administrator pre-creates the device and owns its configuration; the
		// client only attaches to it and must not change anything.
		run("ip", "tuntap", "add", "dev", "wst0", "mode", "tun")
		run("ip", "link", "set", "wst0", "mtu", "1400")
		run("ip", "addr", "add", "198.18.0.1/32", "dev", "wst0")
		run("ip", "link", "set", "wst0", "up")
		run("ip", "route", "add", tunTargetNet, "dev", "wst0")
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

	if err := waitUntil(10*time.Second, func() bool {
		out, err := exec.Command("ip", "route", "show", tunTargetNet).CombinedOutput()
		return err == nil && strings.Contains(string(out), "wst0")
	}); err != nil {
		t.Fatalf("the client did not create wst0 with its route: %v", err)
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

	// Traffic that is not routed into the tunnel must not use it.
	if conn, err := net.DialTimeout("tcp", "198.51.101.9:7", 500*time.Millisecond); err == nil {
		_ = conn.Close()
		t.Fatal("a destination outside the routed network was reachable")
	}

	fmt.Println(tunNetnsOK)
}

// TestTunNetnsHelperEcho is a TCP and UDP echo server for namespace B.
func TestTunNetnsHelperEcho(t *testing.T) {
	addr := os.Getenv(tunEchoEnv)
	if addr == "" {
		t.Skip("runs only as the namespace echo helper")
	}
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
	for {
		c, err := ln.Accept()
		if err != nil {
			t.Fatal(err)
		}
		go func() {
			defer func() { _ = c.Close() }()
			_, _ = io.Copy(c, c)
		}()
	}
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
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
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
