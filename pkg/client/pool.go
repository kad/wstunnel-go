package client

import (
	"context"
	"log/slog"
	"net"
	"time"
)

type ConnectionPool struct {
	client *Client
	conns  chan net.Conn
	ctx    context.Context
	cancel context.CancelFunc
}

func NewConnectionPool(c *Client, minIdle int) *ConnectionPool {
	ctx, cancel := context.WithCancel(context.Background())
	pool := &ConnectionPool{
		client: c,
		conns:  make(chan net.Conn, minIdle), // Buffer size = minIdle
		ctx:    ctx,
		cancel: cancel,
	}

	if minIdle > 0 {
		go pool.maintain(minIdle)
	}

	return pool
}

func (p *ConnectionPool) maintain(minIdle int) {
	ticker := time.NewTicker(100 * time.Millisecond) // Check frequently
	defer ticker.Stop()

	for {
		select {
		case <-p.ctx.Done():
			return
		case <-ticker.C:
			// Fill the pool
			for len(p.conns) < minIdle {
				conn, err := p.client.dialTransport(p.ctx, "", "")
				if err != nil {
					slog.Warn("Pool: failed to dial", "err", err)
					// Backoff a bit
					time.Sleep(1 * time.Second)
					continue
				}

				select {
				case p.conns <- conn:
					slog.Debug("Pool: added connection")
				default:
					// Pool is full (race condition), close conn
					_ = conn.Close()
				}
			}
		}
	}
}

func (p *ConnectionPool) Get(ctx context.Context) (net.Conn, error) {
	select {
	case conn := <-p.conns:
		// Verify connection is still alive?
		// Hard to do without reading. Assuming it's good.
		return conn, nil
	default:
		// Pool empty, dial new one
		return p.client.dialTransport(ctx, "", "")
	}
}

func (p *ConnectionPool) Close() {
	p.cancel()
	for {
		select {
		case conn := <-p.conns:
			if conn != nil {
				_ = conn.Close()
			}
		default:
			return
		}
	}
}
