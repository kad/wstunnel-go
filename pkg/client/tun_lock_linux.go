//go:build linux

package client

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// tunLockDir is where the per-mark lock files live. /run is tried first and the
// temp dir when /run is not writable (an unprivileged or containerised run). A
// variable so tests can use their own directory.
var tunLockDir = "/run"

// acquireTunLock takes an exclusive flock on a lock file named after the
// fwmark and keeps it until release is called or the process ends.
//
// A live full tunnel's rules look exactly like the leftovers of a crashed one,
// so the startup purge asks this lock first: while a live process holds it the
// rules are not stale and the start is refused. A crashed process (even
// SIGKILL) releases the lock with its file descriptors, which is what makes its
// rules stale. The descriptor is close-on-exec, so children do not inherit the
// lock.
func acquireTunLock(mark uint32) (release func(), err error) {
	name := fmt.Sprintf("wstunnel-go-tun-%d.lock", mark)
	var lastErr error
	for _, dir := range []string{tunLockDir, os.TempDir()} {
		f, err := os.OpenFile(filepath.Join(dir, name), os.O_RDWR|os.O_CREATE, 0o600)
		if err != nil {
			lastErr = err
			continue
		}
		if err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
			holder := strings.TrimSpace(readLockPID(f))
			_ = f.Close()
			if err == unix.EWOULDBLOCK {
				who := "another process"
				if holder != "" {
					who = "pid " + holder
				}
				return nil, fmt.Errorf("another full tunnel with mark %#x is running (%s, lock %s); only one full tunnel per mark can run on a host. Stop it, or give this client another --socket-so-mark", mark, who, f.Name())
			}
			return nil, fmt.Errorf("lock %s: %w", f.Name(), err)
		}
		_ = f.Truncate(0)
		_, _ = f.WriteAt([]byte(strconv.Itoa(os.Getpid())+"\n"), 0)
		return func() { _ = f.Close() }, nil // closing the descriptor drops the flock
	}
	return nil, fmt.Errorf("cannot create the full-tunnel lock file %s in %q or %q: %w", name, tunLockDir, os.TempDir(), lastErr)
}

func readLockPID(f *os.File) string {
	buf := make([]byte, 32)
	n, _ := f.ReadAt(buf, 0)
	return string(buf[:n])
}
