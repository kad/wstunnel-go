package tester

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/proxy"
)

var rustBinary string

func init() {
	var err error
	rustBinary, err = exec.LookPath("wstunnel")
	if err != nil {
		fmt.Printf("Rust binary 'wstunnel' not found in PATH: %v\n", err)
		// Leave rustBinary as empty string, tests will skip if not found
	}
}

const (
	// rustBinary   = "/home/kad/repositories/github.com/kad/wstunnel/target/release/wstunnel" // Old hardcoded path
	goBinary = "../../bin/wstunnel-go"
)

type WstunnelProcess struct {
	cmd    *exec.Cmd
	cancel context.CancelFunc
}

func (p *WstunnelProcess) Stop() {
	if p.cancel != nil {
		p.cancel()
	}
	if p.cmd != nil && p.cmd.Process != nil {
		_ = p.cmd.Process.Kill()
		_ = p.cmd.Wait() // Ensure process is reaped
	}
}

func findFreePort(host string) (int, error) {
	ln, err := net.Listen("tcp", net.JoinHostPort(host, "0"))
	if err != nil {
		return 0, err
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()
	return port, nil
}

func startProcess(name string, binary string, args []string, env []string) (*WstunnelProcess, error) {
	ctx, cancel := context.WithCancel(context.Background())
	cmd := exec.CommandContext(ctx, binary, args...)
	if env != nil {
		cmd.Env = env
	}

	// Output logging for debugging
	stdout, _ := cmd.StdoutPipe()
	stderr, _ := cmd.StderrPipe()
	go func() { _, _ = io.Copy(os.Stdout, stdout) }()
	go func() { _, _ = io.Copy(os.Stderr, stderr) }()

	fmt.Printf("[%s] Starting: %s %v\n", name, binary, args)
	if err := cmd.Start(); err != nil {
		cancel()
		return nil, err
	}

	return &WstunnelProcess{cmd: cmd, cancel: cancel}, nil
}

func runEchoServer(port int) (chan struct{}, error) {
	ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		return nil, err
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer func() { _ = ln.Close() }()
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer func() { _ = c.Close() }()
				_, _ = io.Copy(c, c)
			}(conn)
		}
	}()
	return done, nil
}

func runUDPEchoServer(port int) (chan struct{}, error) {
	addr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		return nil, err
	}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return nil, err
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer func() { _ = conn.Close() }()
		buf := make([]byte, 2048)
		for {
			n, src, err := conn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			_, _ = conn.WriteToUDP(buf[:n], src)
		}
	}()
	return done, nil
}

func testTCP(t *testing.T, host string, port int) {
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, fmt.Sprintf("%d", port)), 5*time.Second)
	if err != nil {
		t.Fatalf("TCP: Failed to connect to tunnel port %d: %v", port, err)
	}
	defer func() { _ = conn.Close() }()

	msg := "hello tcp"
	_, _ = conn.Write([]byte(msg))
	buf := make([]byte, len(msg))
	_, err = io.ReadFull(conn, buf)
	if err != nil {
		t.Fatalf("TCP: Failed to read: %v", err)
	}
	if string(buf) != msg {
		t.Fatalf("TCP: Data mismatch: %q vs %q", msg, string(buf))
	}
}

func testUDP(t *testing.T, host string, port int) {
	conn, err := net.Dial("udp", net.JoinHostPort(host, fmt.Sprintf("%d", port)))
	if err != nil {
		t.Fatalf("UDP: Failed to connect: %v", err)
	}
	defer func() { _ = conn.Close() }()

	msg := "hello udp"
	_, _ = conn.Write([]byte(msg))
	buf := make([]byte, len(msg))
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("UDP: Failed to read: %v", err)
	}
	if string(buf[:n]) != msg {
		t.Fatalf("UDP: Data mismatch: %q vs %q", msg, string(buf[:n]))
	}
}

func testSOCKS5(t *testing.T, host string, socksPort int, targetHost string, targetPort int) {
	dialer, err := proxy.SOCKS5("tcp", net.JoinHostPort(host, fmt.Sprintf("%d", socksPort)), nil, proxy.Direct)
	if err != nil {
		t.Fatalf("SOCKS5: Failed to create dialer: %v", err)
	}

	conn, err := dialer.Dial("tcp", fmt.Sprintf("%s:%d", targetHost, targetPort))
	if err != nil {
		t.Fatalf("SOCKS5: Failed to dial through proxy: %v", err)
	}
	defer func() { _ = conn.Close() }()

	msg := "hello socks5"
	_, _ = conn.Write([]byte(msg))
	buf := make([]byte, len(msg))
	_, err = io.ReadFull(conn, buf)
	if err != nil {
		t.Fatalf("SOCKS5: Failed to read: %v", err)
	}
	if string(buf) != msg {
		t.Fatalf("SOCKS5: Data mismatch: %q vs %q", msg, string(buf))
	}
}

func testHTTPProxy(t *testing.T, proxyPort int, targetHost string, targetPort int) {
	// We use a simple TCP echo server, so we can't really use http.Client.Get
	// Instead, we manually do CONNECT
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", proxyPort), 5*time.Second)
	if err != nil {
		t.Fatalf("HTTP Proxy: Failed to connect to proxy: %v", err)
	}
	defer func() { _ = conn.Close() }()

	req := fmt.Sprintf("CONNECT %s:%d HTTP/1.1\r\nHost: %s:%d\r\n\r\n", targetHost, targetPort, targetHost, targetPort)
	_, _ = conn.Write([]byte(req))

	respBuf := make([]byte, 1024)
	n, err := conn.Read(respBuf)
	if err != nil {
		t.Fatalf("HTTP Proxy: Failed to read response from proxy: %v", err)
	}
	if !strings.Contains(string(respBuf[:n]), "200 Connection Established") {
		t.Fatalf("HTTP Proxy: Unexpected response from proxy: %q", string(respBuf[:n]))
	}

	msg := "hello http proxy"
	_, _ = conn.Write([]byte(msg))
	buf := make([]byte, len(msg))
	_, err = io.ReadFull(conn, buf)
	if err != nil {
		t.Fatalf("HTTP Proxy: Failed to read data: %v", err)
	}
	if string(buf) != msg {
		t.Fatalf("HTTP Proxy: Data mismatch: %q vs %q", msg, string(buf))
	}
}

func testReverseTCP(t *testing.T, listenPort int, echoServerPort int) {
	// In reverse tunnel, the client listens on echoServerPort and forwards to server's listenPort.
	// But in wstunnel terms, -R tcp://listenPort:localhost:echoServerPort
	// means the SERVER listens on listenPort and forwards to client, which forwards to localhost:echoServerPort.
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", listenPort), 5*time.Second)
	if err != nil {
		t.Fatalf("Reverse TCP: Failed to connect to server-side listen port %d: %v", listenPort, err)
	}
	defer func() { _ = conn.Close() }()

	msg := "hello reverse tcp"
	_, _ = conn.Write([]byte(msg))
	buf := make([]byte, len(msg))
	_, err = io.ReadFull(conn, buf)
	if err != nil {
		t.Fatalf("Reverse TCP: Failed to read: %v", err)
	}
	if string(buf) != msg {
		t.Fatalf("Reverse TCP: Data mismatch: %q vs %q", msg, string(buf))
	}
}

func runUnixEchoServer(path string) (chan struct{}, error) {
	_ = os.Remove(path)
	ln, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer func() { _ = ln.Close() }()
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer func() { _ = c.Close() }()
				_, _ = io.Copy(c, c)
			}(conn)
		}
	}()
	return done, nil
}

func testUnix(t *testing.T, path string) {
	conn, err := net.DialTimeout("unix", path, 5*time.Second)
	if err != nil {
		t.Fatalf("Unix: Failed to connect to socket %s: %v", path, err)
	}
	defer func() { _ = conn.Close() }()

	msg := "hello unix"
	_, _ = conn.Write([]byte(msg))
	buf := make([]byte, len(msg))
	_, err = io.ReadFull(conn, buf)
	if err != nil {
		t.Fatalf("Unix: Failed to read: %v", err)
	}
	if string(buf) != msg {
		t.Fatalf("Unix: Data mismatch: %q vs %q", msg, string(buf))
	}
}

func TestInteroperability(t *testing.T) {
	if rustBinary == "" { // Check if exec.LookPath found the binary
		t.Skipf("Rust binary 'wstunnel' not found in PATH. Skipping Rust interoperability tests.")
	}
	if _, err := os.Stat(goBinary); os.IsNotExist(err) {
		t.Fatalf("Go binary not found at %s. Run 'make build' first.", goBinary)
	}

	// Create a clean environment for processes to avoid unintended proxy usage.
	var cleanEnv []string
	for _, env := range os.Environ() {
		parts := strings.SplitN(env, "=", 2)
		if len(parts) > 0 {
			key := strings.ToUpper(parts[0])
			if !strings.HasSuffix(key, "_PROXY") {
				cleanEnv = append(cleanEnv, env)
			}
		}
	}

	combinations := []struct {
		name      string
		serverBin string
		clientBin string
		transport string
		ipv6      bool
		isUnix    bool
		options   []string
	}{
		{"Go-Go-WS", goBinary, goBinary, "websocket", false, false, nil},
		{"Go-Rust-WS", goBinary, rustBinary, "websocket", false, false, nil},
		{"Rust-Go-WS", rustBinary, goBinary, "websocket", false, false, nil},
		{"Go-Go-H2", goBinary, goBinary, "http2", false, false, nil},
		{"Go-Rust-H2", goBinary, rustBinary, "http2", false, false, nil},
		{"Rust-Go-H2", rustBinary, goBinary, "http2", false, false, nil},
		{"Go-Go-H2-HTTPS", goBinary, goBinary, "https", false, false, nil},
		{"Go-Go-WS-IPv6", goBinary, goBinary, "websocket", true, false, nil},
		{"Go-Go-WS-Mask", goBinary, goBinary, "websocket", false, false, []string{"--websocket-mask-frame"}},
		{"Go-Go-WS-Ping", goBinary, goBinary, "websocket", false, false, []string{"--websocket-ping-frequency", "10s"}},
		{"Go-Go-Unix", goBinary, goBinary, "websocket", false, true, nil},
		{"Go-Go-HTTPProxy", goBinary, goBinary, "websocket", false, false, []string{"http-proxy"}},
		{"Go-Go-WS-TLS", goBinary, goBinary, "wss", false, false, nil},
		{"Go-Go-H2-TLS", goBinary, goBinary, "https", false, false, nil},
		{"Go-Go-WS-mTLS", goBinary, goBinary, "wss", false, false, []string{"mtls"}},
	}

	for _, tc := range combinations {
		tc := tc // capture range variable
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			host := "127.0.0.1"
			if tc.ipv6 {
				host = "::1"
			}

			serverPort, _ := findFreePort(host)
			tcpPort, _ := findFreePort(host)
			udpPort, _ := findFreePort(host)
			socksPort, _ := findFreePort(host)
			httpProxyPort, _ := findFreePort(host)
			targetPort, _ := findFreePort(host)
			reversePort, _ := findFreePort(host)

			var certFile, keyFile string
			var caCertFile, caKeyFile string
			var clientCertFile, clientKeyFile string

			isTLS := strings.Contains(tc.transport, "wss") || strings.Contains(tc.transport, "https") || tc.name == "Go-Go-H2-HTTPS"
			isMTLS := false
			for _, opt := range tc.options {
				if opt == "mtls" {
					isMTLS = true
				}
			}

			if isTLS {
				certFile = fmt.Sprintf("/tmp/wst-cert-%d.pem", serverPort)
				keyFile = fmt.Sprintf("/tmp/wst-key-%d.pem", serverPort)
				
				if isMTLS {
					caCertFile = fmt.Sprintf("/tmp/wst-ca-%d.pem", serverPort)
					caKeyFile = fmt.Sprintf("/tmp/wst-ca-key-%d.pem", serverPort)
					clientCertFile = fmt.Sprintf("/tmp/wst-client-%d.pem", serverPort)
					clientKeyFile = fmt.Sprintf("/tmp/wst-client-key-%d.pem", serverPort)

					if err := generateCA(caCertFile, caKeyFile); err != nil {
						t.Fatalf("Failed to generate CA: %v", err)
					}
					if err := generateSignedCerts(certFile, keyFile, caCertFile, caKeyFile); err != nil {
						t.Fatalf("Failed to generate server certs: %v", err)
					}
					if err := generateSignedCerts(clientCertFile, clientKeyFile, caCertFile, caKeyFile); err != nil {
						t.Fatalf("Failed to generate client certs: %v", err)
					}
					defer func() { _ = os.Remove(caCertFile) }()
					defer func() { _ = os.Remove(caKeyFile) }()
					defer func() { _ = os.Remove(clientCertFile) }()
					defer func() { _ = os.Remove(clientKeyFile) }()
				} else {
					if err := generateCerts(certFile, keyFile); err != nil {
						t.Fatalf("Failed to generate certs: %v", err)
					}
				}
				defer func() { _ = os.Remove(certFile) }()
				defer func() { _ = os.Remove(keyFile) }()
			}

			var unixTarget string
			var unixListen string
			if tc.isUnix {
				unixTarget = fmt.Sprintf("/tmp/wst-target-%d.sock", serverPort)
				unixListen = fmt.Sprintf("/tmp/wst-listen-%d.sock", serverPort)
				defer func() { _ = os.Remove(unixTarget) }()
				defer func() { _ = os.Remove(unixListen) }()

				echoDone, _ := runUnixEchoServer(unixTarget)
				defer func() { _ = echoDone }()
			}

			// Start Echo Server (TCP)
			echoDone, _ := runEchoServer(targetPort)
			defer func() { _ = echoDone }()

			// Start UDP Echo Server
			udpEchoDone, _ := runUDPEchoServer(targetPort)
			defer func() { _ = udpEchoDone }()

			// Start Wstunnel Server
			serverAddr := net.JoinHostPort(host, fmt.Sprintf("%d", serverPort))
			serverURL := ""
			if strings.HasPrefix(tc.transport, "ws") {
				serverURL = "ws://" + serverAddr
				if isTLS {
					serverURL = "wss://" + serverAddr
				}
			} else if strings.HasPrefix(tc.transport, "http") {
				serverURL = "http://" + serverAddr
				if isTLS {
					serverURL = "https://" + serverAddr
				}
			}
			
			var serverArgs []string
			if tc.serverBin == goBinary {
				serverArgs = []string{"server", "--http-upgrade-path-prefix", "v1", serverURL}
			} else {
				serverArgs = []string{"server", serverURL}
			}

			if isTLS {
				serverArgs = append(serverArgs, "--tls-certificate", certFile, "--tls-private-key", keyFile)
				if isMTLS {
					serverArgs = append(serverArgs, "--tls-client-ca-certs", caCertFile)
				}
				if tc.name == "Go-Go-H2-HTTPS" { // For this specific test case, relax server cert verification
					serverArgs = append(serverArgs, "--tls-verify-certificate=false")
				}
			}

			// Add server-side options if any
			for _, opt := range tc.options {
				if opt != "reverse" && opt != "http-proxy" && opt != "mtls" {
					serverArgs = append(serverArgs, opt)
				}
			}
			
			srv, err := startProcess("Server-"+tc.name, tc.serverBin, serverArgs, cleanEnv)
			if err != nil {
				t.Fatalf("Failed to start server: %v", err)
			}
			defer srv.Stop()

			time.Sleep(1 * time.Second)

			// Start Wstunnel Client
			var clientArgs []string
			// Use RFC 2732 brackets for IPv6 in tunnel arguments
			tcpL := fmt.Sprintf("tcp://%s:127.0.0.1:%d", net.JoinHostPort(host, fmt.Sprintf("%d", tcpPort)), targetPort)
			udpL := fmt.Sprintf("udp://%s:127.0.0.1:%d", net.JoinHostPort(host, fmt.Sprintf("%d", udpPort)), targetPort)
			socksL := fmt.Sprintf("socks5://%s", net.JoinHostPort(host, fmt.Sprintf("%d", socksPort)))
			httpProxyL := fmt.Sprintf("http://%s", net.JoinHostPort(host, fmt.Sprintf("%d", httpProxyPort)))

			connectURL := ""
			switch tc.transport {
			case "websocket":
				connectURL = "ws://" + serverAddr
			case "wss":
				connectURL = "wss://" + serverAddr
			case "http2":
				connectURL = "http://" + serverAddr
			case "https":
				connectURL = "https://" + serverAddr
			}

			clientArgs = []string{"client", "--http-upgrade-path-prefix", "v1", "-L", tcpL, "-L", udpL, "-L", socksL}
			if tc.name == "Go-Go-HTTPProxy" {
				clientArgs = append(clientArgs, "-L", httpProxyL)
			}
			if tc.isUnix {
				clientArgs = append(clientArgs, "-L", fmt.Sprintf("unix://%s:%s", unixListen, unixTarget))
			}
			
			if isTLS {
				clientArgs = append(clientArgs, "--tls-verify-certificate=false")
				if isMTLS {
					clientArgs = append(clientArgs, "--tls-certificate", clientCertFile, "--tls-private-key", clientKeyFile)
				}
			}

			isReverse := false
			for _, opt := range tc.options {
				if opt == "reverse" {
					isReverse = true
					// Server listens on reversePort, client forwards to targetPort
					revArg := fmt.Sprintf("tcp://127.0.0.1:%d:127.0.0.1:%d", reversePort, targetPort)
					clientArgs = append(clientArgs, "-R", revArg)
				} else if opt != "http-proxy" && opt != "mtls" {
					clientArgs = append(clientArgs, opt)
				}
			}

			clientArgs = append(clientArgs, connectURL)
			
			cli, err := startProcess("Client-"+tc.name, tc.clientBin, clientArgs, cleanEnv)
			if err != nil {
				t.Fatalf("Failed to start client: %v", err)
			}
			defer cli.Stop()

			time.Sleep(2 * time.Second)

			// Test TCP
			t.Run("TCP", func(t *testing.T) { testTCP(t, host, tcpPort) })
			// Test UDP
			t.Run("UDP", func(t *testing.T) { testUDP(t, host, udpPort) })
			// Test SOCKS5
			t.Run("SOCKS5", func(t *testing.T) { testSOCKS5(t, host, socksPort, "127.0.0.1", targetPort) })

			if tc.name == "Go-Go-HTTPProxy" {
				t.Run("HTTPProxy", func(t *testing.T) { testHTTPProxy(t, httpProxyPort, "127.0.0.1", targetPort) })
			}
			if isReverse {
				t.Run("ReverseTCP", func(t *testing.T) { testReverseTCP(t, reversePort, targetPort) })
			}
			if tc.isUnix {
				t.Run("Unix", func(t *testing.T) { testUnix(t, unixListen) })
			}

		})
	}
}
