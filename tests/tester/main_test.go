package tester

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"testing"
	"time"

	"golang.org/x/net/proxy"
)

const (
	rustBinary = "/home/kad/repositories/github.com/kad/wstunnel/target/release/wstunnel"
	goBinary   = "../../bin/wstunnel-go"
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
	}
}

func findFreePort() (int, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()
	return port, nil
}

func startProcess(name string, binary string, args ...string) (*WstunnelProcess, error) {
	ctx, cancel := context.WithCancel(context.Background())
	cmd := exec.CommandContext(ctx, binary, args...)
	
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

func testTCP(t *testing.T, port int) {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 5*time.Second)
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

func testUDP(t *testing.T, port int) {
	conn, err := net.Dial("udp", fmt.Sprintf("127.0.0.1:%d", port))
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

func testSOCKS5(t *testing.T, socksPort int, targetHost string, targetPort int) {
	dialer, err := proxy.SOCKS5("tcp", fmt.Sprintf("127.0.0.1:%d", socksPort), nil, proxy.Direct)
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

func TestInteroperability(t *testing.T) {
	if _, err := os.Stat(rustBinary); os.IsNotExist(err) {
		t.Skipf("Rust binary not found at %s", rustBinary)
	}
	if _, err := os.Stat(goBinary); os.IsNotExist(err) {
		t.Fatalf("Go binary not found at %s. Run 'make build' first.", goBinary)
	}

	combinations := []struct {
		name      string
		serverBin string
		clientBin string
		transport string
	}{
		{"Go-Go-WS", goBinary, goBinary, "websocket"},
		{"Go-Rust-WS", goBinary, rustBinary, "websocket"},
		{"Rust-Go-WS", rustBinary, goBinary, "websocket"},
		{"Go-Go-H2", goBinary, goBinary, "http2"},
		{"Go-Rust-H2", goBinary, rustBinary, "http2"},
		{"Rust-Go-H2", rustBinary, goBinary, "http2"},
	}

	for _, tc := range combinations {
		t.Run(tc.name, func(t *testing.T) {
			serverPort, _ := findFreePort()
			tcpPort, _ := findFreePort()
			udpPort, _ := findFreePort()
			socksPort, _ := findFreePort()
			targetPort, _ := findFreePort()

			// Start Echo Server (TCP)
			echoDone, _ := runEchoServer(targetPort)
			defer func() { _ = echoDone }()

			// Start UDP Echo Server
			udpEchoDone, _ := runUDPEchoServer(targetPort)
			defer func() { _ = udpEchoDone }()

			// Start Wstunnel Server
			var serverArgs []string
			serverAddr := fmt.Sprintf("127.0.0.1:%d", serverPort)
			if tc.serverBin == goBinary {
				serverArgs = []string{"server", "--prefix", "v1", "--listen", "ws://" + serverAddr}
			} else {
				serverArgs = []string{"server", "ws://" + serverAddr} // Rust server takes address as direct arg
			}
			srv, err := startProcess("Server-"+tc.name, tc.serverBin, serverArgs...)
			if err != nil {
				t.Fatalf("Failed to start server: %v", err)
			}
			defer srv.Stop()

			time.Sleep(1 * time.Second)

			// Start Wstunnel Client
			var clientArgs []string
			tcpL := fmt.Sprintf("tcp://127.0.0.1:%d:127.0.0.1:%d", tcpPort, targetPort)
			udpL := fmt.Sprintf("udp://127.0.0.1:%d:127.0.0.1:%d", udpPort, targetPort)
			socksL := fmt.Sprintf("socks5://127.0.0.1:%d", socksPort)

			serverURL := ""
			if tc.transport == "websocket" {
				serverURL = "ws://" + serverAddr
			} else {
				serverURL = "http://" + serverAddr
			}

			if tc.clientBin == goBinary {
				clientArgs = []string{"client", "-t", tc.transport, "-L", tcpL, "-L", udpL, "-L", socksL, serverURL}
			} else {
				// Rust client: transport is part of the URL scheme, and prefix for Rust is fixed to v1.
				clientArgs = []string{"client", "--http-upgrade-path-prefix", "v1", "-L", tcpL, "-L", udpL, "-L", socksL, serverURL}
			}
			
			cli, err := startProcess("Client-"+tc.name, tc.clientBin, clientArgs...)
			if err != nil {
				t.Fatalf("Failed to start client: %v", err)
			}
			defer cli.Stop()

			time.Sleep(2 * time.Second)

			// Test TCP
			t.Run("TCP", func(t *testing.T) { testTCP(t, tcpPort) })
			// Test UDP
			t.Run("UDP", func(t *testing.T) { testUDP(t, udpPort) })
			// Test SOCKS5
			t.Run("SOCKS5", func(t *testing.T) { testSOCKS5(t, socksPort, "127.0.0.1", targetPort) })
		})
	}
}