//go:build linux

package client

import (
	"bufio"
	"context"
	"net"
	"os"
	"os/exec"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

const lockHelperEnv = "WST_TUN_LOCK_HELPER"

// TestTunLockHelper is the child of TestTunLockCrash: it takes the lock for the
// mark in the given directory and idles until killed.
func TestTunLockHelper(t *testing.T) {
	dir := os.Getenv(lockHelperEnv)
	if dir == "" {
		t.Skip("runs only as the child of TestTunLockCrash")
	}
	tunLockDir = dir
	if _, err := acquireTunLock(0x7774); err != nil {
		_, _ = os.Stdout.WriteString("ERR " + err.Error() + "\n")
		return
	}
	_, _ = os.Stdout.WriteString("LOCKED\n")
	time.Sleep(time.Minute)
}

func useLockDir(t *testing.T) {
	t.Helper()
	orig := tunLockDir
	tunLockDir = t.TempDir()
	t.Cleanup(func() { tunLockDir = orig })
}

func TestTunLockIsExclusivePerMark(t *testing.T) {
	useLockDir(t)
	release, err := acquireTunLock(0x7774)
	if err != nil {
		t.Fatal(err)
	}
	_, err = acquireTunLock(0x7774)
	if err == nil {
		t.Fatal("a second lock for the same mark was granted")
	}
	for _, want := range []string{"another full tunnel with mark 0x7774", "pid " + strconv.Itoa(os.Getpid())} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q lacks %q", err, want)
		}
	}
	other, err := acquireTunLock(0x7775)
	if err != nil {
		t.Fatalf("a different mark must not be blocked: %v", err)
	}
	other()
	release()
	again, err := acquireTunLock(0x7774)
	if err != nil {
		t.Fatalf("the lock was not released: %v", err)
	}
	again()
}

// A process that dies without cleaning up (SIGKILL) releases the lock, so its
// leftovers are stale and the next start may purge them.
func TestTunLockCrash(t *testing.T) {
	useLockDir(t)
	cmd := exec.Command(os.Args[0], "-test.run=^TestTunLockHelper$")
	cmd.Env = append(os.Environ(), lockHelperEnv+"="+tunLockDir)
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	line, _ := bufio.NewReader(out).ReadString('\n')
	if strings.TrimSpace(line) != "LOCKED" {
		t.Fatalf("helper said %q", line)
	}
	_, err = acquireTunLock(0x7774)
	if err == nil || !strings.Contains(err.Error(), "pid "+strconv.Itoa(cmd.Process.Pid)) {
		t.Fatalf("err = %v, want a refusal naming the child's pid", err)
	}
	_ = cmd.Process.Signal(syscall.SIGKILL)
	_ = cmd.Wait()
	release, err := acquireTunLock(0x7774)
	if err != nil {
		t.Fatalf("lock still held after the holder was killed: %v", err)
	}
	release()
}

func TestTunLockFallsBackToTempDir(t *testing.T) {
	orig := tunLockDir
	tunLockDir = "/nonexistent-dir-for-test/none"
	t.Cleanup(func() { tunLockDir = orig })
	release, err := acquireTunLock(0x7776)
	if err != nil {
		t.Fatalf("no fallback to the temp dir: %v", err)
	}
	release()
}

// Two clients with the same mark: the second must refuse and must not delete the
// first one's rules.
func TestSecondFullTunnelWithTheSameMarkRefusesAndLeavesTheFirstAlone(t *testing.T) {
	srv := newTestTunServer(t, "rust", "")
	host, _, _ := net.SplitHostPort(srv.addr)
	f1 := newFakeHost(t, host)
	f2 := newFakeHost(t, host)
	f2.nl = f1.nl // the same kernel
	f2.deps.nl = f1.nl
	useLockDir(t)

	cfg := Config{ServerURL: "ws://" + srv.addr, PathPrefix: "v1", WebsocketProtocol: "rust"}
	_, h1 := startFullTunnel(t, f1, cfg, "tun://wst0?route=default&routing=fwmark")
	rules := func() []ruleSpec {
		f1.nl.mu.Lock()
		defer f1.nl.mu.Unlock()
		return slices.Clone(f1.nl.existingRules)
	}
	before := rules()
	if len(before) == 0 {
		t.Fatal("first tunnel installed no rules")
	}

	c2 := NewClient(cfg)
	_, err := c2.startTun(context.Background(), mustSpec(t, "tun://wst1?route=default&routing=fwmark"), f2.deps, fastRetry)
	if err == nil || !strings.Contains(err.Error(), "another full tunnel with mark") {
		t.Fatalf("second start: err = %v, want a refusal", err)
	}
	if !slices.Equal(rules(), before) {
		t.Fatalf("the second start changed the first one's rules: %v", rules())
	}
	if f2.opened != 0 {
		t.Error("the second start opened a device")
	}
	if c2.fullTunnelMark.Load() != 0 {
		t.Error("the refused client kept its mark")
	}

	// Once the first one stops, the lock is free again.
	if err := h1.Close(); err != nil {
		t.Fatal(err)
	}
	c3 := NewClient(cfg)
	h3, err := c3.startTun(context.Background(), mustSpec(t, "tun://wst1?route=default&routing=fwmark"), f2.deps, fastRetry)
	if err != nil {
		t.Fatalf("start after the first tunnel closed: %v", err)
	}
	_ = h3.Close()
}

func TestFailedStartReleasesTheLock(t *testing.T) {
	srv := newTestTunServer(t, "rust", "")
	host, _, _ := net.SplitHostPort(srv.addr)
	f := newFakeHost(t, host)
	useLockDir(t)
	f.nl.failOn = "rule add ipv4 pref 32761 not fwmark 0x7774 table 30580"
	f.nl.failErr = syscall.EPERM
	c := NewClient(Config{ServerURL: "ws://" + srv.addr, PathPrefix: "v1", WebsocketProtocol: "rust"})
	if _, err := c.startTun(context.Background(), mustSpec(t, "tun://wst0?route=default&routing=fwmark"), f.deps, fastRetry); err == nil {
		t.Fatal("start succeeded")
	}
	release, err := acquireTunLock(0x7774)
	if err != nil {
		t.Fatalf("a failed start kept the lock: %v", err)
	}
	release()
}
