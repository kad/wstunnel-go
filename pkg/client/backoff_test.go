package client

import (
	"testing"
	"time"
)

func TestSharedBackoffCountsOneRound(t *testing.T) {
	var b sharedBackoff
	started := time.Now()
	time.Sleep(time.Millisecond)

	if _, escalated := b.fail(started, time.Minute); !escalated {
		t.Fatal("first failure should escalate")
	}
	// Seven more tunnels that began at the same time must not escalate again.
	for range 7 {
		if _, escalated := b.fail(started, time.Minute); escalated {
			t.Fatal("failure from the same round escalated")
		}
	}
	if b.failures != 1 {
		t.Fatalf("failures = %d, want 1", b.failures)
	}

	time.Sleep(time.Millisecond)
	if _, escalated := b.fail(time.Now(), time.Minute); !escalated {
		t.Fatal("failure from a later attempt should escalate")
	}
	if b.failures != 2 {
		t.Fatalf("failures = %d, want 2", b.failures)
	}

	b.success()
	if b.failures != 0 {
		t.Fatalf("failures = %d after success, want 0", b.failures)
	}
}

func TestSharedBackoffCapsDelay(t *testing.T) {
	var b sharedBackoff
	for range 10 {
		time.Sleep(time.Millisecond)
		d, _ := b.fail(time.Now(), 4*time.Second)
		if d > 6*time.Second {
			t.Fatalf("delay %v exceeds cap plus jitter", d)
		}
	}
}
