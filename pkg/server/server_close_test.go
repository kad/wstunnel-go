package server

import (
	"errors"
	"net/http"
	"testing"
	"time"
)

func TestServerCloseEndsTunSessionsAndRefusesNewOnes(t *testing.T) {
	for _, tr := range tunTransports {
		t.Run(tr.name, func(t *testing.T) {
			s := NewServer(Config{WebsocketProtocol: tr.mode, EnableTun: true})
			s.SetRules(tunRules(t, tunLoopbackRules))
			addr := startTunServer(t, s)

			pc, err := tr.dial(t, addr, tunToken(t, 1500))
			if err != nil {
				t.Fatalf("dial: %v", err)
			}
			defer func() { _ = pc.Close() }()

			// Wait until the session is really being served: a server that
			// accepted the upgrade answers nothing until it has traffic, so
			// watch the slot instead.
			deadline := time.Now().Add(3 * time.Second)
			for len(s.tunSessionSlots) == 0 {
				if time.Now().After(deadline) {
					t.Fatal("the session never started")
				}
				time.Sleep(10 * time.Millisecond)
			}

			if err := s.Close(); err != nil {
				t.Fatalf("Close: %v", err)
			}

			read := make(chan error, 1)
			go func() {
				_, err := pc.ReadPacket()
				read <- err
			}()
			select {
			case err := <-read:
				if err == nil {
					t.Fatal("ReadPacket returned a packet from a closed server")
				}
			case <-time.After(3 * time.Second):
				t.Fatal("the tun session survived Server.Close")
			}

			if err := waitSessionSlotsFree(s); err != nil {
				t.Fatal(err)
			}

			_, err = tr.dial(t, addr, tunToken(t, 1500))
			var se *statusError
			if !errors.As(err, &se) || se.code != http.StatusServiceUnavailable {
				t.Fatalf("dial after Close = %v, want 503 Service Unavailable", err)
			}
		})
	}
}

func waitSessionSlotsFree(s *Server) error {
	deadline := time.Now().Add(3 * time.Second)
	for len(s.tunSessionSlots) != 0 {
		if time.Now().After(deadline) {
			return errors.New("the session slot was not released after Close")
		}
		time.Sleep(10 * time.Millisecond)
	}
	return nil
}

func TestServerCloseIsIdempotent(t *testing.T) {
	s := NewServer(Config{EnableTun: true})
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
}

func TestTunMTUBelowMinimumIsRefusedBeforeTheUpgrade(t *testing.T) {
	for _, tr := range tunTransports {
		t.Run(tr.name, func(t *testing.T) {
			s := NewServer(Config{WebsocketProtocol: tr.mode, EnableTun: true})
			addr := startTunServer(t, s)

			for _, mtu := range []uint16{1, 576, 1279} {
				_, err := tr.dial(t, addr, tunToken(t, mtu))
				var se *statusError
				if !errors.As(err, &se) || se.code != http.StatusBadRequest {
					t.Errorf("mtu %d: dial = %v, want 400 Bad Request", mtu, err)
				}
			}
			// The default (0) and the minimum are accepted.
			for _, mtu := range []uint16{0, 1280} {
				pc, err := tr.dial(t, addr, tunToken(t, mtu))
				if err != nil {
					t.Errorf("mtu %d: dial = %v, want success", mtu, err)
					continue
				}
				_ = pc.Close()
			}
		})
	}
}
