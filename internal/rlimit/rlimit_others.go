//go:build !linux && !darwin

package rlimit

func RaiseFdLimit() {
	// No-op for non-unix platforms
}
