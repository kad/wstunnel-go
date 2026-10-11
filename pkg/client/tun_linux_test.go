//go:build linux

package client

import (
	"errors"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func TestDescribeTunOpenError(t *testing.T) {
	busy := describeTunOpenError("wst0", unix.EBUSY).Error()
	if !strings.Contains(busy, "already attached") || strings.Contains(busy, "CAP_NET_ADMIN") {
		t.Errorf("EBUSY message %q should say the device is in use, not mention capabilities", busy)
	}
	perm := describeTunOpenError("wst0", unix.EPERM).Error()
	if !strings.Contains(perm, "CAP_NET_ADMIN") {
		t.Errorf("EPERM message %q should mention CAP_NET_ADMIN", perm)
	}
	if err := describeTunOpenError("wst0", unix.EBUSY); !errors.Is(err, unix.EBUSY) {
		t.Error("the cause must stay wrapped")
	}
}
