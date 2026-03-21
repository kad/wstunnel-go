package client

import (
	"context"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

type ConnectionPool struct {
	client *Client
	conns  chan net.Conn
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
	closed atomic.Bool
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
		pool.wg.Add(1)
		go pool.maintain(minIdle)
	}

	return pool
}

func (p *ConnectionPool) maintain(minIdle int) {
	defer p.wg.Done()
	ticker := time.NewTicker(100 * time.Millisecond) // Check frequently
	defer ticker.Stop()

	for {
		select {
		case <-p.ctx.Done():
			return
		case <-ticker.C:
			// Fill the pool
			for len(p.conns) < minIdle {
				select {
				case <-p.ctx.Done():
					return
				default:
				}

				conn, err := p.client.dialTransport(p.ctx, "", "")
				if err != nil {
					slog.Warn("Pool: failed to dial", "err", err)
					select {
					case <-p.ctx.Done():
						return
					case <-time.After(1 * time.Second):
					}
					continue
				}

				select {
				case <-p.ctx.Done():
					_ = conn.Close()
					return
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
	if p.closed.Load() {
		return nil, net.ErrClosed
	}

	select {
	case conn := <-p.conns:
		if p.closed.Load() {
			if conn != nil {
				_ = conn.Close()
			}
			return nil, net.ErrClosed
		}
		// Verify connection is still alive?
		// Hard to do without reading. Assuming it's good.
		return conn, nil
	default:
		if p.closed.Load() {
			return nil, net.ErrClosed
		}
		// Pool empty, dial new one
		conn, err := p.client.dialTransport(ctx, "", "")
		if err != nil {
			return nil, err
		}
		if p.closed.Load() {
			_ = conn.Close()
			return nil, net.ErrClosed
		}
		return conn, nil
	}
}

func (p *ConnectionPool) Close() {
	p.closed.Store(true)
	if p.cancel != nil {
		p.cancel()
	}
	p.wg.Wait()
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
