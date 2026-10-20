package tunnel

import (
	"io"
	"sync/atomic"
	"time"
)

// Liveness is the evidence a watchdog uses to decide a peer is alive. It is
// shared with the pipe the watchdog guards, so the pipe can report what the
// connection alone cannot show:
//
//   - data is still arriving (Touch), including inside a message that has not
//     finished yet, and
//   - the pipe itself is blocked writing the peer's data to a slow local
//     destination and so is not reading the connection, which says nothing
//     about the peer.
//
// All methods are safe on a nil *Liveness, which stands for "no watchdog".
type Liveness struct {
	last    atomic.Int64 // unix nanoseconds of the last sign of life
	stalled atomic.Int32 // downstream writes in progress
}

func newLiveness() *Liveness {
	l := &Liveness{}
	l.Touch()
	return l
}

// Touch records a sign of life from the peer.
func (l *Liveness) Touch() {
	if l != nil {
		l.last.Store(time.Now().UnixNano())
	}
}

// idle is how long the peer has shown no sign of life. It is zero while the
// pipe is blocked writing downstream, because it cannot read the peer then.
func (l *Liveness) idle() time.Duration {
	if l.stalled.Load() > 0 {
		return 0
	}
	return time.Since(time.Unix(0, l.last.Load()))
}

// block suspends the idle check until the returned func is called, for time the
// reader spends stuck on something other than the peer: a write to a slow
// destination, or a pong that waits for the write lock behind a bulk write. The
// peer cannot be judged while we are not reading it.
func (l *Liveness) block() (unblock func()) {
	if l == nil {
		return func() {}
	}
	l.stalled.Add(1)
	return func() {
		// Refresh before clearing the stalled count. The watchdog reads the
		// count first, so once it sees no stalled work the timestamp is
		// already fresh; the other order leaves a gap in which a long block
		// looks like silence and a healthy peer gets closed.
		l.Touch()
		l.stalled.Add(-1)
	}
}

// writer wraps dst so that a blocked Write suspends the idle check, and a Write
// that finishes counts as the pipe being responsive again.
func (l *Liveness) writer(dst io.Writer) io.Writer {
	if l == nil {
		return dst
	}
	return liveWriter{dst, l}
}

type liveWriter struct {
	dst io.Writer
	l   *Liveness
}

func (w liveWriter) Write(p []byte) (int, error) {
	defer w.l.block()()
	return w.dst.Write(p)
}

// reader wraps src so that each chunk read from the peer counts as life.
func (l *Liveness) reader(src io.Reader) io.Reader {
	if l == nil {
		return src
	}
	return liveReader{src, l}
}

type liveReader struct {
	src io.Reader
	l   *Liveness
}

func (r liveReader) Read(p []byte) (int, error) {
	n, err := r.src.Read(p)
	if n > 0 {
		r.l.Touch()
	}
	return n, err
}
