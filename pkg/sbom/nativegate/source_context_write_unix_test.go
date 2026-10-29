//go:build linux || darwin

package nativegate

import (
	"context"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func TestContextWriteFailure(t *testing.T) {
	if filename := os.Getenv("DK_TEST_CONTEXT_WRITE_FAILURE"); filename != "" {
		signal.Ignore(syscall.SIGXFSZ)
		var limit syscall.Rlimit
		if err := syscall.Getrlimit(syscall.RLIMIT_FSIZE, &limit); err != nil {
			t.Fatal(err)
		}
		limit.Cur = 1
		if err := syscall.Setrlimit(syscall.RLIMIT_FSIZE, &limit); err != nil {
			t.Fatal(err)
		}
		if err := writeContext(filename, []byte("context payload")); err == nil {
			t.Fatal("expected the file size limit to reject the context write")
		}
		if _, err := os.Stat(filename); !os.IsNotExist(err) {
			t.Fatalf("failed write left a context file: %v", err)
		}
		return
	}

	filename := filepath.Join(t.TempDir(), "context.json")
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestContextWriteFailure$")
	cmd.Env = append(os.Environ(), "DK_TEST_CONTEXT_WRITE_FAILURE="+filename)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("write-fault child failed: %v\n%s", err, output)
	}
	if _, err := os.Stat(filename); !os.IsNotExist(err) {
		t.Fatalf("partial context remains after the child exits: %v", err)
	}
}
