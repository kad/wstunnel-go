package client

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"slices"
	"testing"

	"github.com/quic-go/quic-go"
)

func TestWebTransportQUICConfigKeepsIdleSessionsAlive(t *testing.T) {
	cfg := newWebTransportQUICConfig()
	if cfg.KeepAlivePeriod <= 0 {
		t.Fatal("KeepAlivePeriod is unset: idle WebTransport sessions are dropped by the QUIC idle timeout")
	}
	// quic-go's idle timeout defaults to 30s when MaxIdleTimeout is zero.
	idle := cfg.MaxIdleTimeout
	if idle == 0 {
		idle = 30e9
	}
	if cfg.KeepAlivePeriod >= idle {
		t.Fatalf("KeepAlivePeriod %v must be below the idle timeout %v", cfg.KeepAlivePeriod, idle)
	}
	if !cfg.EnableDatagrams || !cfg.EnableStreamResetPartialDelivery {
		t.Fatal("webtransport-go requires datagrams and stream reset partial delivery")
	}
}

type fakeSession struct{ ctx context.Context }

func (f fakeSession) Context() context.Context { return f.ctx }

func TestSessionDead(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	if sessionDead(fakeSession{ctx}) {
		t.Fatal("a live session was reported dead")
	}
	cancel()
	if !sessionDead(fakeSession{ctx}) {
		t.Fatal("an ended session was not reported dead")
	}
}

func TestWebTransportDialsPinnedAddressesInOrder(t *testing.T) {
	c := NewClient(Config{ServerURL: "wts://tun-server.invalid:4433"})
	// A resolver that always fails: the pinned addresses must not need it.
	c.resolver.Store(&net.Resolver{PreferGo: true, Dial: func(context.Context, string, string) (net.Conn, error) {
		return nil, errors.New("dns down")
	}})
	c.serverAddrs.Store(&[]netip.Addr{netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2")})
	w := NewWebTransportClient(c)

	var tried []string
	conn, err := w.dialAddrs(context.Background(), "tun-server.invalid:4433", func(a *net.UDPAddr) (*quic.Conn, error) {
		tried = append(tried, a.String())
		if a.IP.String() == "192.0.2.1" {
			return nil, errors.New("unreachable")
		}
		return &quic.Conn{}, nil
	})
	if err != nil || conn == nil {
		t.Fatalf("dialAddrs = %v, %v", conn, err)
	}
	if want := []string{"192.0.2.1:4433", "192.0.2.2:4433"}; !slices.Equal(tried, want) {
		t.Fatalf("tried %v, want %v (first success wins)", tried, want)
	}

	// All failing: the error carries every attempt.
	_, err = w.dialAddrs(context.Background(), "tun-server.invalid:4433", func(*net.UDPAddr) (*quic.Conn, error) {
		return nil, errors.New("unreachable")
	})
	if err == nil {
		t.Fatal("no error although every address failed")
	}
}
