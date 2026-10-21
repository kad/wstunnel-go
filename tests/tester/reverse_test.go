package tester

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/proxy"
)

// reverseCase is one server/client pairing and transport for the reverse tunnel
// tests. The server is the side that listens for visitors; the client is the one
// that dials the target.
type reverseCase struct {
	name       string
	serverBin  string
	clientBin  string
	scheme     string // URL scheme of the tunnel server
	serverOpts []string
	clientOpts []string
	tls        bool // the server needs a certificate and the client does not verify it
	skip       string
	// byteStreamUDP is set for a transport that carries UDP as a plain byte
	// stream (HTTP/2, as in Rust): it cannot keep an empty datagram or a very
	// large one apart from its neighbours.
	byteStreamUDP bool
}

func reverseCases() []reverseCase {
	return []reverseCase{
		{name: "Go-Go-WS", serverBin: goBinary, clientBin: goBinary, scheme: "ws"},
		{name: "Go-Go-WS-RFC", serverBin: goBinary, clientBin: goBinary, scheme: "ws", serverOpts: []string{"--mode", "ws"}, clientOpts: []string{"--mode", "ws"}},
		{name: "Go-Rust-WS", serverBin: goBinary, clientBin: rustBinary, scheme: "ws"},
		{name: "Rust-Go-WS", serverBin: rustBinary, clientBin: goBinary, scheme: "ws"},
		{name: "Go-Go-H2", serverBin: goBinary, clientBin: goBinary, scheme: "http", byteStreamUDP: true},
		{name: "Go-Go-WT", serverBin: goBinary, clientBin: goBinary, scheme: "wt"},
		// Rust speaks WebTransport over TLS only (11.x).
		{name: "Go-Go-WTS", serverBin: goBinary, clientBin: goBinary, scheme: "wts", tls: true},
		{name: "Go-Rust-WTS", serverBin: goBinary, clientBin: rustBinary, scheme: "wts", tls: true},
		{name: "Rust-Go-WTS", serverBin: rustBinary, clientBin: goBinary, scheme: "wts", tls: true,
			skip: "the Go WebTransport client needs QUIC stream reset partial delivery, which Rust's server does not enable"},
		{name: "Go-Rust-H2", serverBin: goBinary, clientBin: rustBinary, scheme: "http", byteStreamUDP: true},
		// Rust v10.5.2 panics in its cleartext H2 auto-detect server path unless ping is disabled.
		{name: "Rust-Go-H2", serverBin: rustBinary, clientBin: goBinary, scheme: "http", byteStreamUDP: true, serverOpts: []string{"--websocket-ping-frequency", "0s"}},
	}
}

// rustHasWebTransport reports whether the installed Rust wstunnel speaks
// WebTransport, which it has since 10.7.0. An older one rejects wts:// outright.
func rustHasWebTransport() bool {
	out, err := exec.Command(rustBinary, "--version").Output()
	if err != nil {
		return false
	}
	var major, minor int
	fields := strings.Fields(string(out))
	if len(fields) == 0 {
		return false
	}
	if _, err := fmt.Sscanf(fields[len(fields)-1], "%d.%d", &major, &minor); err != nil {
		return false
	}
	return major > 10 || (major == 10 && minor >= 7)
}

// skipReason says why tc cannot run here, or "" when it can.
func (tc reverseCase) skipReason() string {
	if tc.skip != "" {
		return tc.skip
	}
	usesRust := tc.serverBin == rustBinary || tc.clientBin == rustBinary
	if usesRust && strings.HasPrefix(tc.scheme, "wt") && !rustHasWebTransport() {
		return "the installed Rust wstunnel has no WebTransport (needs 10.7.0 or newer)"
	}
	return ""
}

// reverseEnv is the process environment without proxy variables, which would
// otherwise send the loopback traffic of the test through a proxy.
func reverseEnv() []string {
	var env []string
	for _, e := range os.Environ() {
		if !strings.HasSuffix(strings.ToUpper(strings.SplitN(e, "=", 2)[0]), "_PROXY") {
			env = append(env, e)
		}
	}
	return env
}

// startReverse runs a tunnel server and a client that publishes reverseArg on
// it, and returns once the client is up.
func startReverse(t *testing.T, tc reverseCase, host string, serverPort int, reverseArg string) {
	t.Helper()
	startTunnel(t, tc, host, serverPort, "-R", reverseArg)
}

// startTunnel starts the case's server and a client with one tunnel argument:
// "-R" for a reverse tunnel, "-L" for a forward one.
func startTunnel(t *testing.T, tc reverseCase, host string, serverPort int, flag, tunnelArg string) {
	t.Helper()
	env := reverseEnv()
	serverURL := fmt.Sprintf("%s://%s", tc.scheme, net.JoinHostPort(host, fmt.Sprint(serverPort)))

	serverArgs := []string{"server"}
	if tc.serverBin == goBinary {
		serverArgs = []string{"--log-lvl", "DEBUG", "server", "--http-upgrade-path-prefix", "v1"}
	}
	serverArgs = append(serverArgs, tc.serverOpts...)
	if tc.tls {
		certFile := fmt.Sprintf("/tmp/wst-rev-cert-%d.pem", serverPort)
		keyFile := fmt.Sprintf("/tmp/wst-rev-key-%d.pem", serverPort)
		if err := generateCerts(certFile, keyFile); err != nil {
			t.Fatalf("generate certificates: %v", err)
		}
		t.Cleanup(func() { _ = os.Remove(certFile); _ = os.Remove(keyFile) })
		serverArgs = append(serverArgs, "--tls-certificate", certFile, "--tls-private-key", keyFile)
	}
	serverArgs = append(serverArgs, serverURL)
	srv, err := startProcess("Server-"+tc.name, tc.serverBin, serverArgs, env)
	if err != nil {
		t.Fatalf("start server: %v", err)
	}
	t.Cleanup(srv.Stop)
	if err := waitForPort(host, serverPort, 5*time.Second); err != nil {
		t.Fatalf("server did not start: %v", err)
	}

	clientArgs := []string{"client"}
	if tc.clientBin == goBinary {
		clientArgs = []string{"--log-lvl", "DEBUG", "client", "--http-upgrade-path-prefix", "v1"}
	}
	clientArgs = append(clientArgs, flag, tunnelArg)
	clientArgs = append(clientArgs, tc.clientOpts...)
	if tc.tls && tc.clientBin == goBinary {
		// Rust does not verify the server certificate unless asked to.
		clientArgs = append(clientArgs, "--tls-verify-certificate=false")
	}
	clientArgs = append(clientArgs, serverURL)
	cli, err := startProcess("Client-"+tc.name, tc.clientBin, clientArgs, env)
	if err != nil {
		t.Fatalf("start client: %v", err)
	}
	t.Cleanup(cli.Stop)
}

// reverseUDPSession sends datagrams from one UDP socket, a single peer for the
// whole call. The listener only exists once the client has connected, so the
// first datagram is retried until it is echoed; the rest then go through the
// session that datagram created and must each come back.
func reverseUDPSession(t *testing.T, host string, port int, msgs ...[]byte) {
	t.Helper()
	conn, err := net.Dial("udp", net.JoinHostPort(host, fmt.Sprint(port)))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = conn.Close() }()

	buf := make([]byte, 65535)
	bootstrap := msgs[0]
	bootstrapEchoes := false // set once the retries of the first datagram may have left copies queued
	exchange := func(msg []byte, wait time.Duration) error {
		if _, err := conn.Write(msg); err != nil {
			return err
		}
		_ = conn.SetReadDeadline(time.Now().Add(wait))
		for {
			n, err := conn.Read(buf)
			if err != nil {
				return err
			}
			if bootstrapEchoes && !bytes.Equal(msg, bootstrap) && bytes.Equal(buf[:n], bootstrap) {
				continue // a late echo of a retry of the first datagram, not an answer to msg
			}
			if !bytes.Equal(buf[:n], msg) {
				t.Fatalf("echo mismatch: sent %d bytes, got %d", len(msg), n)
			}
			return nil
		}
	}

	deadline := time.Now().Add(15 * time.Second)
	var lastErr error
	for {
		if lastErr = exchange(msgs[0], 700*time.Millisecond); lastErr == nil {
			bootstrapEchoes = true
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("no UDP echo through the reverse tunnel: %v", lastErr)
		}
		time.Sleep(100 * time.Millisecond)
	}
	for i, msg := range msgs[1:] {
		if err := exchange(msg, 5*time.Second); err != nil {
			t.Fatalf("datagram %d of the session (%d bytes) did not come back: %v", i+2, len(msg), err)
		}
	}
}

func TestReverseUDP(t *testing.T) {
	if rustBinary == "" {
		t.Skip("Rust binary 'wstunnel' not found in PATH. Skipping reverse interoperability tests.")
	}
	if _, err := os.Stat(goBinary); os.IsNotExist(err) {
		t.Fatalf("Go binary not found at %s. Run 'make build' first.", goBinary)
	}
	for _, tc := range reverseCases() {
		t.Run(tc.name, func(t *testing.T) {
			if reason := tc.skipReason(); reason != "" {
				t.Skip(reason)
			}
			host := "127.0.0.1"
			serverPort, err := findFreeTCPUDPPort(host) // WebTransport listens on UDP at the same port
			if err != nil {
				t.Fatal(err)
			}
			targetPort, err := findFreeUDPPort(host)
			if err != nil {
				t.Fatal(err)
			}
			reversePort, err := findFreeUDPPort(host)
			if err != nil {
				t.Fatal(err)
			}
			echo, err := runUDPEchoServer(targetPort)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = echo }()

			startReverse(t, tc, host, serverPort, fmt.Sprintf("udp://%s:%d:%s:%d", host, reversePort, host, targetPort))

			// One peer, one session: several distinct datagrams through the
			// connection the first one was given.
			msgs := [][]byte{[]byte("hello reverse udp"), []byte("second datagram"), []byte("third datagram")}
			if !tc.byteStreamUDP {
				msgs = append(msgs, bytes.Repeat([]byte{0x5A}, 60000))
				// Rust does not carry an empty datagram over WebSocket, so only two
				// Go peers can be asked to.
				if tc.serverBin == goBinary && tc.clientBin == goBinary {
					msgs = append(msgs, nil, []byte("after the empty one"))
				}
			}
			reverseUDPSession(t, host, reversePort, msgs...)

			// A second peer gets a session of its own.
			reverseUDPSession(t, host, reversePort, []byte("another peer"), []byte("and its second datagram"))

			// Several peers at once each get a client connection of their own.
			var wg sync.WaitGroup
			for i := range 4 {
				wg.Add(1)
				go func() {
					defer wg.Done()
					reverseUDPSession(t, host, reversePort, []byte(fmt.Sprintf("concurrent peer %d", i)), []byte("again"))
				}()
			}
			wg.Wait()
		})
	}
}

// reverseSocks5Echo connects through the server's reverse SOCKS5 port to the
// target and checks the echo. The listener only exists once the client has
// connected, so the first attempts may be refused.
func reverseSocks5Echo(t *testing.T, host string, socksPort int, targetHost string, targetPort int, msg string, auth *proxy.Auth) {
	t.Helper()
	dialer, err := proxy.SOCKS5("tcp", net.JoinHostPort(host, fmt.Sprint(socksPort)), auth, proxy.Direct)
	if err != nil {
		t.Fatalf("socks5 dialer: %v", err)
	}
	deadline := time.Now().Add(20 * time.Second)
	var lastErr error
	for time.Now().Before(deadline) {
		conn, err := dialer.Dial("tcp", net.JoinHostPort(targetHost, fmt.Sprint(targetPort)))
		if err != nil {
			lastErr = err
			time.Sleep(300 * time.Millisecond)
			continue
		}
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		if _, err := conn.Write([]byte(msg)); err != nil {
			_ = conn.Close()
			lastErr = err
			time.Sleep(300 * time.Millisecond)
			continue
		}
		buf := make([]byte, len(msg))
		_, err = io.ReadFull(conn, buf)
		_ = conn.Close()
		if err != nil {
			lastErr = err
			time.Sleep(300 * time.Millisecond)
			continue
		}
		if string(buf) != msg {
			t.Fatalf("echo mismatch: sent %q, got %q", msg, buf)
		}
		return
	}
	t.Fatalf("no echo through the reverse SOCKS5 tunnel: %v", lastErr)
}

func TestReverseSocks5(t *testing.T) {
	if rustBinary == "" {
		t.Skip("Rust binary 'wstunnel' not found in PATH. Skipping reverse interoperability tests.")
	}
	if _, err := os.Stat(goBinary); os.IsNotExist(err) {
		t.Fatalf("Go binary not found at %s. Run 'make build' first.", goBinary)
	}
	for _, tc := range reverseCases() {
		for _, withAuth := range []bool{false, true} {
			name := tc.name
			if withAuth {
				name += "-auth"
			}
			t.Run(name, func(t *testing.T) {
				if reason := tc.skipReason(); reason != "" {
					t.Skip(reason)
				}
				host := "127.0.0.1"
				serverPort, err := findFreeTCPUDPPort(host) // WebTransport listens on UDP at the same port
				if err != nil {
					t.Fatal(err)
				}
				targetPort, err := findFreeTCPPort(host)
				if err != nil {
					t.Fatal(err)
				}
				socksPort, err := findFreeTCPPort(host)
				if err != nil {
					t.Fatal(err)
				}
				echo, err := runEchoServer(targetPort)
				if err != nil {
					t.Fatal(err)
				}
				defer func() { _ = echo }()

				arg := fmt.Sprintf("socks5://%s:%d", host, socksPort)
				var auth *proxy.Auth
				if withAuth {
					arg += "?login=admin&password=secret"
					auth = &proxy.Auth{User: "admin", Password: "secret"}
				}
				startReverse(t, tc, host, serverPort, arg)
				reverseSocks5Echo(t, host, socksPort, host, targetPort, "hello reverse socks5", auth)

				if withAuth {
					// Wrong credentials are refused by the server's SOCKS5 listener.
					bad, err := proxy.SOCKS5("tcp", net.JoinHostPort(host, fmt.Sprint(socksPort)), &proxy.Auth{User: "admin", Password: "wrong"}, proxy.Direct)
					if err != nil {
						t.Fatal(err)
					}
					if conn, err := bad.Dial("tcp", net.JoinHostPort(host, fmt.Sprint(targetPort))); err == nil {
						_ = conn.Close()
						t.Fatal("a visitor with the wrong password got through")
					}
				}

				// Several visitors at once each reach the target through the client.
				var wg sync.WaitGroup
				for i := range 4 {
					wg.Add(1)
					go func() {
						defer wg.Done()
						reverseSocks5Echo(t, host, socksPort, host, targetPort, fmt.Sprintf("visitor %d", i), auth)
					}()
				}
				wg.Wait()
			})
		}
	}
}

// reverseHTTPProxyConnect opens a CONNECT tunnel through the server's reverse HTTP
// proxy port and checks an echo through it. The listener only exists once the
// client has connected, so the first attempts may be refused.
func reverseHTTPProxyConnect(t *testing.T, proxyAddr, targetAddr, msg, authHeader string) {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	var lastErr error
	for time.Now().Before(deadline) {
		err := func() error {
			conn, err := net.DialTimeout("tcp", proxyAddr, 2*time.Second)
			if err != nil {
				return err
			}
			defer func() { _ = conn.Close() }()
			_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
			req := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n%s\r\n", targetAddr, targetAddr, authHeader)
			if _, err := io.WriteString(conn, req); err != nil {
				return err
			}
			// Read the response head byte by byte, so nothing of the tunnel is consumed.
			var head []byte
			one := make([]byte, 1)
			for !bytes.HasSuffix(head, []byte("\r\n\r\n")) {
				if _, err := conn.Read(one); err != nil {
					return err
				}
				head = append(head, one[0])
			}
			if !strings.HasPrefix(string(head), "HTTP/1.1 200") {
				return fmt.Errorf("proxy answered %q", strings.SplitN(string(head), "\r\n", 2)[0])
			}
			if _, err := io.WriteString(conn, msg); err != nil {
				return err
			}
			buf := make([]byte, len(msg))
			if _, err := io.ReadFull(conn, buf); err != nil {
				return err
			}
			if string(buf) != msg {
				t.Fatalf("echo mismatch: sent %q, got %q", msg, buf)
			}
			return nil
		}()
		if err == nil {
			return
		}
		lastErr = err
		time.Sleep(300 * time.Millisecond)
	}
	t.Fatalf("no echo through the reverse HTTP proxy tunnel: %v", lastErr)
}

func TestReverseHTTPProxy(t *testing.T) {
	if rustBinary == "" {
		t.Skip("Rust binary 'wstunnel' not found in PATH. Skipping reverse interoperability tests.")
	}
	if _, err := os.Stat(goBinary); os.IsNotExist(err) {
		t.Fatalf("Go binary not found at %s. Run 'make build' first.", goBinary)
	}
	for _, tc := range reverseCases() {
		for _, withAuth := range []bool{false, true} {
			name := tc.name
			if withAuth {
				name += "-auth"
			}
			t.Run(name, func(t *testing.T) {
				if reason := tc.skipReason(); reason != "" {
					t.Skip(reason)
				}
				host := "127.0.0.1"
				serverPort, err := findFreeTCPUDPPort(host) // WebTransport listens on UDP at the same port
				if err != nil {
					t.Fatal(err)
				}
				targetPort, err := findFreeTCPPort(host)
				if err != nil {
					t.Fatal(err)
				}
				proxyPort, err := findFreeTCPPort(host)
				if err != nil {
					t.Fatal(err)
				}
				// The target answers plain HTTP, and echoes anything else.
				echo, err := runEchoServer(targetPort)
				if err != nil {
					t.Fatal(err)
				}
				defer func() { _ = echo }()

				arg := fmt.Sprintf("http://%s:%d", host, proxyPort)
				authHeader := ""
				if withAuth {
					arg += "?login=admin&password=secret"
					authHeader = "Proxy-Authorization: Basic YWRtaW46c2VjcmV0\r\n" // admin:secret
				}
				startReverse(t, tc, host, serverPort, arg)
				proxyAddr := net.JoinHostPort(host, fmt.Sprint(proxyPort))
				targetAddr := net.JoinHostPort(host, fmt.Sprint(targetPort))
				reverseHTTPProxyConnect(t, proxyAddr, targetAddr, "hello reverse http proxy", authHeader)

				if withAuth {
					// Without the credentials the visitor is challenged.
					conn, err := net.DialTimeout("tcp", proxyAddr, 2*time.Second)
					if err != nil {
						t.Fatal(err)
					}
					defer func() { _ = conn.Close() }()
					_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
					_, _ = fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", targetAddr, targetAddr)
					line, _ := io.ReadAll(conn)
					if !strings.HasPrefix(string(line), "HTTP/1.1 407") && !strings.HasPrefix(string(line), "HTTP/1.0 407") {
						t.Fatalf("a visitor without credentials got %q, want a 407", line)
					}
				}

				// Several visitors at once each reach the target through the client.
				var wg sync.WaitGroup
				for i := range 4 {
					wg.Add(1)
					go func() {
						defer wg.Done()
						reverseHTTPProxyConnect(t, proxyAddr, targetAddr, fmt.Sprintf("visitor %d", i), authHeader)
					}()
				}
				wg.Wait()
			})
		}
	}
}

// A plain (non-CONNECT) request through the reverse HTTP proxy reaches the
// target as it was sent.
func TestReverseHTTPProxyPlainRequest(t *testing.T) {
	if rustBinary == "" {
		t.Skip("Rust binary 'wstunnel' not found in PATH. Skipping reverse interoperability tests.")
	}
	if _, err := os.Stat(goBinary); os.IsNotExist(err) {
		t.Fatalf("Go binary not found at %s. Run 'make build' first.", goBinary)
	}
	for _, tc := range reverseCases() {
		t.Run(tc.name, func(t *testing.T) {
			if reason := tc.skipReason(); reason != "" {
				t.Skip(reason)
			}
			host := "127.0.0.1"
			serverPort, err := findFreeTCPUDPPort(host) // WebTransport listens on UDP at the same port
			if err != nil {
				t.Fatal(err)
			}
			proxyPort, err := findFreeTCPPort(host)
			if err != nil {
				t.Fatal(err)
			}
			target, err := net.Listen("tcp", host+":0")
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = target.Close() }()
			go func() {
				for {
					c, err := target.Accept()
					if err != nil {
						return
					}
					go func() {
						defer func() { _ = c.Close() }()
						_ = c.SetDeadline(time.Now().Add(10 * time.Second))
						var req []byte
						one := make([]byte, 1)
						for !bytes.HasSuffix(req, []byte("\r\n\r\n")) {
							if _, err := c.Read(one); err != nil {
								return
							}
							req = append(req, one[0])
						}
						line := strings.SplitN(string(req), "\r\n", 2)[0]
						body := "you asked: " + line
						_, _ = fmt.Fprintf(c, "HTTP/1.1 200 OK\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", len(body), body)
					}()
				}
			}()

			startReverse(t, tc, host, serverPort, fmt.Sprintf("http://%s:%d", host, proxyPort))

			targetURL := "http://" + target.Addr().String() + "/hello"
			deadline := time.Now().Add(20 * time.Second)
			var lastErr error
			for time.Now().Before(deadline) {
				conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, fmt.Sprint(proxyPort)), 2*time.Second)
				if err != nil {
					lastErr = err
					time.Sleep(300 * time.Millisecond)
					continue
				}
				_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
				_, _ = fmt.Fprintf(conn, "GET %s HTTP/1.1\r\nHost: %s\r\n\r\n", targetURL, target.Addr())
				got, _ := io.ReadAll(conn)
				_ = conn.Close()
				if strings.Contains(string(got), "you asked: GET "+targetURL) {
					return
				}
				lastErr = fmt.Errorf("unexpected response %q", got)
				time.Sleep(300 * time.Millisecond)
			}
			t.Fatalf("plain request through the reverse HTTP proxy failed: %v", lastErr)
		})
	}
}

// socks5UDPAssociate asks the SOCKS5 server for a UDP relay and returns the
// address to send datagrams to, with the TCP connection that keeps it alive. A
// relay bound to every address is reached at the host the connection used.
func socks5UDPAssociate(socksAddr string, user, pass string) (*net.UDPAddr, net.Conn, error) {
	conn, err := net.DialTimeout("tcp", socksAddr, 2*time.Second)
	if err != nil {
		return nil, nil, err
	}
	fail := func(err error) (*net.UDPAddr, net.Conn, error) {
		_ = conn.Close()
		return nil, nil, err
	}
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	method := byte(0x00)
	if user != "" {
		method = 0x02
	}
	if _, err := conn.Write([]byte{5, 1, method}); err != nil {
		return fail(err)
	}
	greeting := make([]byte, 2)
	if _, err := io.ReadFull(conn, greeting); err != nil || greeting[1] != method {
		return fail(fmt.Errorf("greeting %v: %v", greeting, err))
	}
	if user != "" {
		auth := append(append([]byte{1, byte(len(user))}, user...), byte(len(pass)))
		if _, err := conn.Write(append(auth, pass...)); err != nil {
			return fail(err)
		}
		status := make([]byte, 2)
		if _, err := io.ReadFull(conn, status); err != nil || status[1] != 0 {
			return fail(fmt.Errorf("authentication refused: %v %v", status, err))
		}
	}
	if _, err := conn.Write([]byte{5, 3, 0, 1, 0, 0, 0, 0, 0, 0}); err != nil {
		return fail(err)
	}
	reply := make([]byte, 10)
	if _, err := io.ReadFull(conn, reply); err != nil || reply[1] != 0 || reply[3] != 1 {
		return fail(fmt.Errorf("associate reply %v: %v", reply, err))
	}
	_ = conn.SetDeadline(time.Time{})
	relay := &net.UDPAddr{IP: net.IP(reply[4:8]), Port: int(reply[8])<<8 | int(reply[9])}
	if relay.IP.IsUnspecified() {
		relay.IP = conn.RemoteAddr().(*net.TCPAddr).IP
	}
	return relay, conn, nil
}

// reverseSocks5UDPEcho sends a datagram for the UDP echo target through the
// reverse SOCKS5 relay and checks the answer. The listener only exists once the
// client has connected, so the first attempts may fail.
func reverseSocks5UDPEcho(t *testing.T, socksAddr string, user, pass string, targetPort int, msg string, burst bool) {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	var lastErr error
	for time.Now().Before(deadline) {
		err := func() error {
			relay, ctrl, err := socks5UDPAssociate(socksAddr, user, pass)
			if err != nil {
				return err
			}
			defer func() { _ = ctrl.Close() }()
			sock, err := net.DialUDP("udp", nil, relay)
			if err != nil {
				return err
			}
			defer func() { _ = sock.Close() }()
			// SOCKS5 UDP header for 127.0.0.1:targetPort.
			header := []byte{0, 0, 0, 1, 127, 0, 0, 1, byte(targetPort >> 8), byte(targetPort)}
			// Two datagrams on one session, to check the session carries on.
			for _, m := range []string{msg, msg + " again"} {
				if _, err := sock.Write(append(append([]byte(nil), header...), m...)); err != nil {
					return err
				}
				_ = sock.SetReadDeadline(time.Now().Add(3 * time.Second))
				buf := make([]byte, 2048)
				n, err := sock.Read(buf)
				if err != nil {
					return err
				}
				if n < len(header) {
					return fmt.Errorf("short answer %v", buf[:n])
				}
				if !bytes.Equal(buf[3:len(header)], header[3:]) {
					return fmt.Errorf("answer header %v, want the target's %v", buf[:len(header)], header)
				}
				if got := string(buf[len(header):n]); got != m {
					t.Fatalf("echo mismatch: sent %q, got %q", m, got)
				}
			}
			if burst {
				// Datagrams sent back to back must come back as they went, one
				// by one, on transports that keep boundaries.
				sent := []string{"a", "bb", strings.Repeat("c", 1200), "dddd"}
				for _, m := range sent {
					if _, err := sock.Write(append(append([]byte(nil), header...), m...)); err != nil {
						return err
					}
				}
				for _, m := range sent {
					_ = sock.SetReadDeadline(time.Now().Add(3 * time.Second))
					buf := make([]byte, 4096)
					n, err := sock.Read(buf)
					if err != nil {
						return err
					}
					if n < len(header) || string(buf[len(header):n]) != m {
						t.Fatalf("burst datagram: sent %d bytes, got %d bytes back", len(m), n-len(header))
					}
				}
			}
			return nil
		}()
		if err == nil {
			return
		}
		lastErr = err
		time.Sleep(300 * time.Millisecond)
	}
	t.Fatalf("no echo through the reverse SOCKS5 UDP relay: %v", lastErr)
}

func TestReverseSocks5UDPAssociate(t *testing.T) {
	if rustBinary == "" {
		t.Skip("Rust binary 'wstunnel' not found in PATH. Skipping reverse interoperability tests.")
	}
	if _, err := os.Stat(goBinary); os.IsNotExist(err) {
		t.Fatalf("Go binary not found at %s. Run 'make build' first.", goBinary)
	}
	for _, tc := range reverseCases() {
		for _, withAuth := range []bool{false, true} {
			name := tc.name
			if withAuth {
				name += "-auth"
			}
			t.Run(name, func(t *testing.T) {
				if reason := tc.skipReason(); reason != "" {
					t.Skip(reason)
				}
				if tc.byteStreamUDP {
					// HTTP/2 carries UDP as a byte stream, which does not keep the
					// datagrams of a session apart; the echo here is one datagram at
					// a time, so it still works.
					t.Log("HTTP/2: datagram boundaries are best effort")
				}
				host := "127.0.0.1"
				serverPort, err := findFreeTCPUDPPort(host) // WebTransport listens on UDP at the same port
				if err != nil {
					t.Fatal(err)
				}
				targetPort, err := findFreeUDPPort(host)
				if err != nil {
					t.Fatal(err)
				}
				socksPort, err := findFreeTCPUDPPort(host)
				if err != nil {
					t.Fatal(err)
				}
				echo, err := runUDPEchoServer(targetPort)
				if err != nil {
					t.Fatal(err)
				}
				defer func() { _ = echo }()

				arg := fmt.Sprintf("socks5://%s:%d", host, socksPort)
				user, pass := "", ""
				if withAuth {
					arg += "?login=admin&password=secret"
					user, pass = "admin", "secret"
				}
				startReverse(t, tc, host, serverPort, arg)
				reverseSocks5UDPEcho(t, net.JoinHostPort(host, fmt.Sprint(socksPort)), user, pass, targetPort, "hello udp associate", !tc.byteStreamUDP)
			})
		}
	}
}

// A forward SOCKS5 listener on the client relays UDP too: datagrams in the SOCKS5
// UDP header go through the tunnel to the destination they name.
func TestForwardSocks5UDPAssociate(t *testing.T) {
	if rustBinary == "" {
		t.Skip("Rust binary 'wstunnel' not found in PATH. Skipping interoperability tests.")
	}
	if _, err := os.Stat(goBinary); os.IsNotExist(err) {
		t.Fatalf("Go binary not found at %s. Run 'make build' first.", goBinary)
	}
	for _, tc := range reverseCases() {
		for _, withAuth := range []bool{false, true} {
			name := tc.name
			if withAuth {
				name += "-auth"
			}
			t.Run(name, func(t *testing.T) {
				if reason := tc.skipReason(); reason != "" {
					t.Skip(reason)
				}
				host := "127.0.0.1"
				serverPort, err := findFreeTCPUDPPort(host) // WebTransport listens on UDP at the same port
				if err != nil {
					t.Fatal(err)
				}
				targetPort, err := findFreeUDPPort(host)
				if err != nil {
					t.Fatal(err)
				}
				socksPort, err := findFreeTCPUDPPort(host)
				if err != nil {
					t.Fatal(err)
				}
				echo, err := runUDPEchoServer(targetPort)
				if err != nil {
					t.Fatal(err)
				}
				defer func() { _ = echo }()

				arg := fmt.Sprintf("socks5://%s:%d", host, socksPort)
				user, pass := "", ""
				if withAuth {
					arg += "?login=admin&password=secret"
					user, pass = "admin", "secret"
				}
				startTunnel(t, tc, host, serverPort, "-L", arg)
				if err := waitForPort(host, socksPort, 10*time.Second); err != nil {
					t.Fatal(err)
				}
				reverseSocks5UDPEcho(t, net.JoinHostPort(host, fmt.Sprint(socksPort)), user, pass, targetPort, "hello forward udp associate", !tc.byteStreamUDP)
			})
		}
	}
}
