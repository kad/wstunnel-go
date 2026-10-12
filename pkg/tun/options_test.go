package tun_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/kad/wstunnel-go/pkg/tun"
	"github.com/kad/wstunnel-go/pkg/tun/tuntest"
)

// A negative timeout would make every dial fail, or every UDP association
// expire, at once: refuse the session instead of serving one that cannot
// forward anything.
func TestServeRejectsNegativeTimeouts(t *testing.T) {
	for name, opts := range map[string]tun.Options{
		"dial timeout":     {DialTimeout: -time.Second},
		"udp idle timeout": {UDPIdleTimeout: -time.Second},
	} {
		t.Run(name, func(t *testing.T) {
			opts.Authorize = func(tun.Flow) bool { return true }
			serverEnd, clientEnd := tuntest.Pipe()
			defer func() { _ = clientEnd.Close() }()
			err := tun.Serve(context.Background(), serverEnd, opts)
			if err == nil || !strings.Contains(err.Error(), "negative") {
				t.Fatalf("Serve = %v, want an error about a negative timeout", err)
			}
		})
	}
}

// Negative limits would panic when the flow budget channel is made, or be
// handed to gVisor as they are: refuse them with an options error.
func TestServeRejectsNegativeLimits(t *testing.T) {
	for name, opts := range map[string]tun.Options{
		"max flows":     {MaxFlows: -1},
		"max in-flight": {MaxInFlightSYN: -1},
	} {
		t.Run(name, func(t *testing.T) {
			opts.Authorize = func(tun.Flow) bool { return true }
			serverEnd, clientEnd := tuntest.Pipe()
			defer func() { _ = clientEnd.Close() }()
			err := tun.Serve(context.Background(), serverEnd, opts)
			if err == nil || !strings.Contains(err.Error(), "negative") {
				t.Fatalf("Serve = %v, want an error about a negative limit", err)
			}
		})
	}
}
