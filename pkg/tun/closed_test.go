package tun

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"syscall"
	"testing"

	"github.com/gorilla/websocket"
)

func TestIsClosedErr(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, true},
		{"eof", io.EOF, true},
		{"unexpected eof", io.ErrUnexpectedEOF, true},
		{"closed pipe", io.ErrClosedPipe, true},
		{"net closed", net.ErrClosed, true},
		{"canceled", context.Canceled, true},
		{"epipe", syscall.EPIPE, true},
		{"econnreset", syscall.ECONNRESET, true},
		{"wrapped econnreset", &net.OpError{Op: "write", Err: fmt.Errorf("x: %w", syscall.ECONNRESET)}, true},
		{"ws close", &websocket.CloseError{Code: websocket.CloseGoingAway}, true},
		{"wrapped ws close", fmt.Errorf("read: %w", &websocket.CloseError{Code: websocket.CloseAbnormalClosure}), true},
		{"ws close sent", websocket.ErrCloseSent, true},
		{"too large", ErrPacketTooLarge, false},
		{"other", errors.New("boom"), false},
		{"deadline", context.DeadlineExceeded, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := isClosedErr(tc.err); got != tc.want {
				t.Fatalf("isClosedErr(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}
