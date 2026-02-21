//go:build !linux

package socket

func SetSoMark(fd uintptr, mark uint32) error {
	return nil
}
