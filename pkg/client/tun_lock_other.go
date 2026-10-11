//go:build !linux

package client

var tunLockDir = ""

func acquireTunLock(uint32) (func(), error) { return func() {}, nil }
