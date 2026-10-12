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

// tunLockDirs lists the directories a lock may live in, primary first.
func tunLockDirs() []string {
	dirs := []string{tunLockDir}
	if tmp := os.TempDir(); tmp != tunLockDir {
		dirs = append(dirs, tmp)
	}
	return dirs
}

// tunLockPath names the lock file for a mark. The policy rules the lock
// protects live in one network namespace, so the namespace is part of the name:
// clients in different namespaces do not block each other.
func tunLockPath(dir string, mark uint32) string {
	name := fmt.Sprintf("wstunnel-go-tun-%d", mark)
	if id, err := os.Readlink("/proc/self/ns/net"); err == nil {
		if digits := strings.Trim(id, "net:[]"); digits != "" {
			name += "-" + digits
		}
	}
	return filepath.Join(dir, name+".lock")
}

// acquireTunLock takes an exclusive flock on a lock file named after the
// fwmark and keeps it until release is called or the process ends.
//
// A live full tunnel's rules look exactly like the leftovers of a crashed one,
// so the startup purge asks this lock first: while a live process holds it the
// rules are not stale and the start is refused. A crashed process (even
// SIGKILL) releases the lock with its file descriptors, which is what makes its
// rules stale. The descriptor is close-on-exec, so children do not inherit the
// lock.
//
// One mark must have one lock domain. The lock is created in the first usable
// directory, but every directory is checked: a lock file that already exists
// must be lockable by us (a conflict refuses the start), and one we cannot even
// open is a client we cannot coordinate with, which also refuses the start
// instead of moving on to a different directory.
func acquireTunLock(mark uint32) (release func(), err error) {
	var held []*os.File
	releaseAll := func() {
		for _, f := range held {
			_ = f.Close() // closing the descriptor drops the flock
		}
	}
	fail := func(err error) (func(), error) {
		releaseAll()
		return nil, err
	}
	var lastErr error
	for _, dir := range tunLockDirs() {
		path := tunLockPath(dir, mark)
		_, statErr := os.Lstat(path)
		exists := statErr == nil
		if !exists && len(held) > 0 {
			continue // we already hold the lock for this mark
		}
		flags := unix.O_RDWR | unix.O_CLOEXEC | unix.O_NOFOLLOW
		if !exists {
			flags |= unix.O_CREAT
		}
		fd, err := unix.Open(path, flags, 0o600)
		if err != nil {
			if exists {
				return fail(fmt.Errorf("the full-tunnel lock %s exists but cannot be opened (%w): a full tunnel with mark %#x was probably started by a more privileged user; run this client as the same user, or stop that one", path, err, mark))
			}
			lastErr = err
			continue
		}
		f := os.NewFile(uintptr(fd), path)
		if err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
			holder := strings.TrimSpace(readLockPID(f))
			_ = f.Close()
			if err == unix.EWOULDBLOCK {
				who := "another process"
				if holder != "" {
					who = "pid " + holder
				}
				return fail(fmt.Errorf("another full tunnel with mark %#x is running (%s, lock %s); only one full tunnel per mark can run on a host. Stop it, or give this client another --socket-so-mark", mark, who, path))
			}
			return fail(fmt.Errorf("lock %s: %w", path, err))
		}
		_ = f.Truncate(0)
		_, _ = f.WriteAt([]byte(strconv.Itoa(os.Getpid())+"\n"), 0)
		held = append(held, f)
	}
	if len(held) == 0 {
		return nil, fmt.Errorf("cannot create the full-tunnel lock file for mark %#x in %v: %w", mark, tunLockDirs(), lastErr)
	}
	return releaseAll, nil
}

func readLockPID(f *os.File) string {
	buf := make([]byte, 32)
	n, _ := f.ReadAt(buf, 0)
	return string(buf[:n])
}
