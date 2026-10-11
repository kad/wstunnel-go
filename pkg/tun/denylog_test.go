package tun

import (
	"testing"
	"time"
)

func TestLogLimiterBurstThenInterval(t *testing.T) {
	var l logLimiter
	base := time.Unix(1_000_000, 0)

	for i := 0; i < denyLogBurst; i++ {
		if ok, suppressed := l.allow(base); !ok || suppressed != 0 {
			t.Fatalf("event %d inside the burst: allow = %v, %d; want true, 0", i, ok, suppressed)
		}
	}
	for i := 0; i < 25; i++ {
		if ok, _ := l.allow(base.Add(time.Second)); ok {
			t.Fatalf("event %d after the burst was logged inside the interval", i)
		}
	}
	ok, suppressed := l.allow(base.Add(denyLogInterval + time.Second))
	if !ok || suppressed != 25 {
		t.Fatalf("first event after the interval: allow = %v, %d; want true, 25", ok, suppressed)
	}
	if ok, _ := l.allow(base.Add(denyLogInterval + 2*time.Second)); ok {
		t.Fatal("an event right after a periodic report was logged again")
	}
}
