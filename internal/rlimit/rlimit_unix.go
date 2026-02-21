//go:build linux || darwin

package rlimit

import (
	"log/slog"
	"syscall"
)

func RaiseFdLimit() {
	var rLimit syscall.Rlimit
	err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &rLimit)
	if err != nil {
		slog.Warn("Failed to get fd limit", "err", err)
		return
	}
	rLimit.Cur = rLimit.Max
	err = syscall.Setrlimit(syscall.RLIMIT_NOFILE, &rLimit)
	if err != nil {
		slog.Warn("Failed to raise fd limit", "err", err)
	}
}
