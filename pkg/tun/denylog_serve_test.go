package tun_test

import (
	"context"
	"log/slog"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kad/wstunnel-go/pkg/tun"
	"github.com/kad/wstunnel-go/pkg/tun/tuntest"
)

// countingHandler counts the log records whose message matches msg.
type countingHandler struct {
	msg string
	n   *atomic.Int64
}

func (h countingHandler) Enabled(context.Context, slog.Level) bool { return true }
func (h countingHandler) Handle(_ context.Context, r slog.Record) error {
	if r.Message == h.msg {
		h.n.Add(1)
	}
	return nil
}
func (h countingHandler) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h countingHandler) WithGroup(string) slog.Handler      { return h }

func TestServeLogsOnlyABurstOfDeniedFlows(t *testing.T) {
	var denied atomic.Int64
	logger := slog.New(countingHandler{msg: "tun flow denied", n: &denied})

	serverEnd, clientEnd := tuntest.Pipe()
	host, _ := startSessionOn(t, serverEnd, clientEnd, tun.Options{
		Authorize: func(tun.Flow) bool { return false },
		Logger:    logger,
	})

	const attempts = 40
	for i := 0; i < attempts; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		dst := netip.AddrPortFrom(netip.MustParseAddr("203.0.113.7"), uint16(1000+i))
		if _, err := host.DialTCP(ctx, dst); err == nil {
			t.Fatalf("attempt %d: a denied flow connected", i)
		}
		cancel()
	}
	if got := denied.Load(); got != tun.DenyLogBurst {
		t.Fatalf("%d denied flows wrote %d log lines, want exactly the burst of %d", attempts, got, tun.DenyLogBurst)
	}
}
