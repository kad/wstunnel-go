package client

import (
	"math/rand/v2"
	"sync"
	"time"
)

// sharedBackoff makes every reverse tunnel of a client back off together, so a
// server or proxy that is down sees one retry round instead of one per tunnel.
// The zero value is ready to use.
type sharedBackoff struct {
	mu       sync.Mutex
	failures int
	until    time.Time
	lastBump time.Time
}

// wait blocks until the shared retry deadline has passed.
func (b *sharedBackoff) wait() {
	for {
		b.mu.Lock()
		d := time.Until(b.until)
		b.mu.Unlock()
		if d <= 0 {
			return
		}
		time.Sleep(d)
	}
}

// fail records a failed attempt that began at started and returns how long
// until the next attempt. escalated is false when the attempt began before the
// last escalation: that failure belongs to a round already counted, so it does
// not lengthen the delay again.
func (b *sharedBackoff) fail(started time.Time, maxDelay time.Duration) (delay time.Duration, escalated bool) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if started.Before(b.lastBump) {
		return max(time.Until(b.until), 0), false
	}

	b.failures++
	delay = time.Second
	for i := 1; i < b.failures && delay < maxDelay; i++ {
		delay *= 2
	}
	delay = min(delay, maxDelay)
	// Jitter spreads the tunnels out once the delay expires.
	delay = delay/2 + time.Duration(rand.Int64N(int64(delay)))

	now := time.Now()
	b.lastBump = now
	b.until = now.Add(delay)
	return delay, true
}

func (b *sharedBackoff) success() {
	b.mu.Lock()
	b.failures = 0
	b.mu.Unlock()
}
