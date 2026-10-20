package tunnel

import (
	"errors"
	"io"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"
	"github.com/kad/wstunnel-go/pkg/wst"
)

// IsTransientWriteTimeout reports whether a control-frame write failed only
// because it waited too long for the write lock or the socket, leaving the
// connection usable. It is true for wst.ErrControlTimeout and for gorilla's own
// lock-wait timeout, which is both Timeout and Temporary. gorilla caches a fatal
// socket write error for good and hides its Temporary flag but keeps Timeout,
// so Timeout alone cannot tell the two apart; such a connection is broken and
// the error must reach the caller's cleanup.
func IsTransientWriteTimeout(err error) bool {
	if errors.Is(err, wst.ErrControlTimeout) {
		return true
	}
	var ne interface {
		Timeout() bool
		Temporary() bool
	}
	return errors.As(err, &ne) && ne.Timeout() && ne.Temporary()
}

// A watchdog is only valid while something reads the connection, because pongs
// are consumed by the reader. Run it around an active pipe, not on a parked
// reverse-tunnel connection (those are bounded by the idle timeout instead).
//
// Any frame from the peer counts as proof of life, not only a pong: a peer that
// is busy streaming data to us can answer a ping late, because the pong queues
// behind its own bulk writes (or is dropped when its send buffer stays full).

// WatchWst pings a custom websocket every interval and closes it when nothing
// came back for three intervals, so a peer that vanished without a TCP close
// ends the pipe instead of holding it open. The returned func stops the
// watchdog; the Liveness goes to the matching PipeLive call.
func WatchWst(c *wst.Conn, interval time.Duration, attrs ...any) (stop func(), l *Liveness) {
	return watchWst(c, interval, true, attrs)
}

// PingWst is WatchWst without the silence limit: it keeps pinging and closes the
// connection only when a ping cannot be written. It is for a connection the
// peer may legitimately not be reading, such as one a legacy server keeps parked.
func PingWst(c *wst.Conn, interval time.Duration, attrs ...any) (stop func(), l *Liveness) {
	return watchWst(c, interval, false, attrs)
}

func watchWst(c *wst.Conn, interval time.Duration, enforce bool, attrs []any) (stop func(), l *Liveness) {
	if interval <= 0 {
		return func() {}, nil
	}
	l = newLiveness()
	c.SetFrameHook(l.Touch)
	// Answer a ping with a bounded write, so the reader is not held up behind
	// a bulk write for longer than a second. The wait still happens in the
	// reader, so it is excluded from the idle time: the peer's frames are
	// queued unread meanwhile, and a short ping interval would otherwise
	// expire before the reader gets back to them.
	c.SetPingHandler(func(appData string) error {
		l.Touch()
		defer l.block()()
		err := c.WriteControl(wst.PongMessage, []byte(appData), time.Now().Add(time.Second))
		if errors.Is(err, io.ErrClosedPipe) || errors.Is(err, net.ErrClosed) || IsTransientWriteTimeout(err) {
			return nil // a dropped pong; see the note above
		}
		return err
	})
	stopDog := runWatchdog(interval, l, enforce, attrs,
		func() error { return skipTransient(c.WriteControl(wst.PingMessage, nil, time.Now().Add(interval))) },
		func() { _ = c.Close() })
	return func() {
		stopDog()
		c.SetFrameHook(nil)
	}, l
}

// WatchGorilla is WatchWst for an RFC 6455 connection. gorilla has no
// per-frame hook, so the Liveness must be handed to PipeGorillaLive (or
// PipeGorillaRWLive), which reports data as it is read; pongs are caught here.
func WatchGorilla(c *websocket.Conn, interval time.Duration, attrs ...any) (stop func(), l *Liveness) {
	return watchGorilla(c, interval, true, attrs)
}

// PingGorilla is PingWst for an RFC 6455 connection.
func PingGorilla(c *websocket.Conn, interval time.Duration, attrs ...any) (stop func(), l *Liveness) {
	return watchGorilla(c, interval, false, attrs)
}

func watchGorilla(c *websocket.Conn, interval time.Duration, enforce bool, attrs []any) (stop func(), l *Liveness) {
	if interval <= 0 {
		return func() {}, nil
	}
	l = newLiveness()
	c.SetPongHandler(func(string) error {
		l.Touch()
		return nil
	})
	c.SetPingHandler(func(appData string) error {
		l.Touch()
		defer l.block()() // the reader waits here; see WatchWst
		err := c.WriteControl(websocket.PongMessage, []byte(appData), time.Now().Add(time.Second))
		if errors.Is(err, websocket.ErrCloseSent) || IsTransientWriteTimeout(err) {
			return nil // a dropped pong; see the note above
		}
		return err
	})
	stop = runWatchdog(interval, l, enforce, attrs,
		func() error {
			return skipTransient(c.WriteControl(websocket.PingMessage, nil, time.Now().Add(interval)))
		},
		func() { _ = c.Close() })
	return stop, l
}

// skipTransient turns a ping that merely timed out into a skipped ping. The
// inactivity check decides when a connection is dead; a peer that keeps sending
// while our bulk writes hold the write lock is not.
func skipTransient(err error) error {
	if IsTransientWriteTimeout(err) {
		return nil
	}
	return err
}

func runWatchdog(interval time.Duration, l *Liveness, enforce bool, attrs []any, ping func() error, closeConn func()) func() {
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
			if idle := l.idle(); enforce && idle > 3*interval {
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
