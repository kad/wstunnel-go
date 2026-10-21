package tester

import (
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestReverseBurst measures how many visitors a burst gets through a reverse TCP
// tunnel (Rust's fc4ff7a was about listen backlog and handoff under bursts). It
// is opt-in, because it opens many connections: set WST_BURST to the number of
// simultaneous visitors, for example WST_BURST=1000 go test ./tests/tester -run
// TestReverseBurst -v.
func TestReverseBurst(t *testing.T) {
	n, _ := strconv.Atoi(os.Getenv("WST_BURST"))
	if n <= 0 {
		t.Skip("set WST_BURST to the number of simultaneous visitors to run the burst measurement")
	}
	if _, err := os.Stat(goBinary); os.IsNotExist(err) {
		t.Fatalf("Go binary not found at %s. Run 'make build' first.", goBinary)
	}
	tc := reverseCase{name: "Go-Go-WS", serverBin: goBinary, clientBin: goBinary, scheme: "ws"}
	host := "127.0.0.1"
	serverPort, _ := findFreeTCPUDPPort(host)
	targetPort, _ := findFreeTCPPort(host)
	revPort, _ := findFreeTCPPort(host)
	echo, err := runEchoServer(targetPort)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = echo }()
	startReverse(t, tc, host, serverPort, fmt.Sprintf("tcp://%d:%s:%d", revPort, host, targetPort))
	if err := waitForPort(host, revPort, 20*time.Second); err != nil {
		t.Fatal(err)
	}

	var ok, failed atomic.Int64
	var slowest atomic.Int64
	var wg sync.WaitGroup
	start := time.Now()
	for i := range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			t0 := time.Now()
			conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, fmt.Sprint(revPort)), 30*time.Second)
			if err != nil {
				failed.Add(1)
				return
			}
			defer func() { _ = conn.Close() }()
			_ = conn.SetDeadline(time.Now().Add(60 * time.Second))
			msg := fmt.Sprintf("visitor %d", i)
			if _, err := io.WriteString(conn, msg); err != nil {
				failed.Add(1)
				return
			}
			buf := make([]byte, len(msg))
			if _, err := io.ReadFull(conn, buf); err != nil || string(buf) != msg {
				failed.Add(1)
				return
			}
			ok.Add(1)
			d := time.Since(t0).Milliseconds()
			for cur := slowest.Load(); d > cur && !slowest.CompareAndSwap(cur, d); cur = slowest.Load() {
			}
		}()
	}
	wg.Wait()
	t.Logf("burst of %d visitors: %d echoed, %d failed, %s in total, slowest %dms",
		n, ok.Load(), failed.Load(), time.Since(start).Round(time.Millisecond), slowest.Load())
	if failed.Load() > 0 {
		t.Errorf("%d of %d visitors in the burst were dropped", failed.Load(), n)
	}
}
