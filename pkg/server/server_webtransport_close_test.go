package server

import (
	"sync"
	"testing"
)

// Close may run while Start is still setting the listener up (a Caddy reload
// or a shutdown signal during startup). The two must not race, and a Start that
// loses the race must not leave a listener running.
func TestWebTransportStartAndCloseDoNotRace(t *testing.T) {
	for range 20 {
		w := NewWebTransportServer(&Server{Config: Config{}})
		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			_ = w.Start("127.0.0.1:0", nil)
		}()
		go func() {
			defer wg.Done()
			_ = w.Close()
		}()
		wg.Wait()
		if err := w.Close(); err != nil {
			t.Errorf("second Close: %v", err)
		}
	}
}

func TestWebTransportStartAfterCloseDoesNotListen(t *testing.T) {
	w := NewWebTransportServer(&Server{Config: Config{}})
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if err := w.Start("127.0.0.1:0", nil); err == nil {
		_ = w.Close()
		t.Fatal("Start after Close succeeded; the listener would outlive the server")
	}
}
