package client

import (
	"context"
	"testing"
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
