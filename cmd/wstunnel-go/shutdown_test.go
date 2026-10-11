package main

import (
	"bufio"
	"context"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"
	"time"
)

const shutdownHelperEnv = "WST_SHUTDOWN_HELPER"

// TestShutdownHelper is the child of TestShutdownSignals: it installs the
// shutdown handling, reports when the first signal arrived, then idles so the
// parent can send a second one.
func TestShutdownHelper(t *testing.T) {
	if os.Getenv(shutdownHelperEnv) == "" {
		t.Skip("runs only as the child of TestShutdownSignals")
	}
	ctx, stop := notifyShutdown(context.Background())
	defer stop()
	_, _ = os.Stdout.WriteString("READY\n")
	<-ctx.Done()
	_, _ = os.Stdout.WriteString("FIRST\n")
	time.Sleep(20 * time.Second) // a second signal must end the process before this
}

func TestShutdownSignals(t *testing.T) {
	for _, first := range []syscall.Signal{syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP} {
		t.Run(first.String(), func(t *testing.T) {
			cmd := exec.Command(os.Args[0], "-test.run=^TestShutdownHelper$")
			cmd.Env = append(os.Environ(), shutdownHelperEnv+"=1")
			out, err := cmd.StdoutPipe()
			if err != nil {
				t.Fatal(err)
			}
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			done := make(chan error, 1)
			go func() { done <- cmd.Wait() }()
			t.Cleanup(func() { _ = cmd.Process.Kill() })

			lines := make(chan string, 8)
			go func() {
				sc := bufio.NewScanner(out)
				for sc.Scan() {
					lines <- strings.TrimSpace(sc.Text())
				}
			}()
			wait := func(want string) {
				t.Helper()
				for {
					select {
					case l := <-lines:
						if l == want {
							return
						}
					case <-time.After(10 * time.Second):
						t.Fatalf("child never printed %q", want)
					}
				}
			}
			wait("READY")
			if err := cmd.Process.Signal(first); err != nil {
				t.Fatal(err)
			}
			wait("FIRST") // the first signal is a request for an orderly shutdown

			// The handlers are released after the first signal, so a second one
			// terminates the process the normal way.
			if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
				t.Fatal(err)
			}
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				t.Fatal("a second signal did not terminate the process")
			}
		})
	}
}
