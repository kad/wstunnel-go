package server

import (
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"
	"github.com/kad/wstunnel-go/pkg/wst"
)

// A watchdog is only valid while something reads the connection, because pongs
// are consumed by the reader. Run it around an active pipe, not on a parked
// reverse-tunnel connection (those are bounded by the idle timeout instead).

// watchWst pings a custom websocket every interval and closes it when no pong
// came back for three intervals, so a peer that vanished without a TCP close
// ends the pipe instead of holding it open. The returned func stops the watchdog.
func watchWst(c *wst.Conn, interval time.Duration, attrs ...any) func() {
	if interval <= 0 {
		return func() {}
	}
	var last atomic.Int64
	last.Store(time.Now().UnixNano())
	c.SetPongHandler(func(string) error {
		last.Store(time.Now().UnixNano())
		return nil
	})
	return runWatchdog(interval, &last, attrs,
		func() error { return c.WriteControl(wst.PingMessage, nil, time.Now().Add(interval)) },
		func() { _ = c.Close() })
}

// watchGorilla is watchWst for an RFC 6455 connection.
func watchGorilla(c *websocket.Conn, interval time.Duration, attrs ...any) func() {
	if interval <= 0 {
		return func() {}
	}
	var last atomic.Int64
	last.Store(time.Now().UnixNano())
	c.SetPongHandler(func(string) error {
		last.Store(time.Now().UnixNano())
		return nil
	})
	return runWatchdog(interval, &last, attrs,
		func() error { return c.WriteControl(websocket.PingMessage, nil, time.Now().Add(interval)) },
		func() { _ = c.Close() })
}

func runWatchdog(interval time.Duration, last *atomic.Int64, attrs []any, ping func() error, closeConn func()) func() {
	done := make(chan struct{})
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		// A ping can block behind a stuck write; keep the idle check running
		// regardless, since closing the connection is what unblocks it.
		var pinging atomic.Bool
		for {
			select {
			case <-done:
				return
			case <-ticker.C:
			}
			if idle := time.Since(time.Unix(0, last.Load())); idle > 3*interval {
				slog.Warn("Tunnel peer unresponsive; closing", append([]any{"idle", idle.Round(time.Second)}, attrs...)...)
				closeConn()
				return
			}
			if pinging.CompareAndSwap(false, true) {
				go func() {
					defer pinging.Store(false)
					if err := ping(); err != nil {
						closeConn()
					}
				}()
			}
		}
	}()
	var once sync.Once
	return func() { once.Do(func() { close(done) }) }
}
