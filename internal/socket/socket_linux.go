//go:build linux

package socket

import "syscall"

func SetSoMark(fd uintptr, mark uint32) error {
	return syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_MARK, int(mark))
}
