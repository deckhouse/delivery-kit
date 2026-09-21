//go:build !windows

package signing

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fakeBsign puts a bsign stub first on PATH. It exits 0 when signing and with
// exitCode when asked to check the hash, which is what the real bsign does to a
// file it rewrote but can no longer hash.
func fakeBsign(t *testing.T, exitCode int) {
	t.Helper()
	dir := t.TempDir()
	script := fmt.Sprintf("#!/bin/sh\nfor arg in \"$@\"; do\n\tif [ \"$arg\" = -c ]; then\n\t\techo 'bsign: invalid hash'\n\t\texit %d\n\tfi\ndone\nexit 0\n", exitCode)
	if err := os.WriteFile(filepath.Join(dir, "bsign"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
}

func TestSignELFFileRejectsUnhashableBsignResult(t *testing.T) {
	fakeBsign(t, 66)

	path := filepath.Join(t.TempDir(), "binary")
	if err := os.WriteFile(path, []byte("payload"), 0o755); err != nil {
		t.Fatal(err)
	}

	err := signELFFile(context.Background(), path, ELFSigningOptions{BsignEnabled: true})
	if err == nil {
		t.Fatal("signing accepted a file bsign cannot hash")
	}
	if !strings.Contains(err.Error(), "hash check") || !strings.Contains(err.Error(), "bad hash") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestSignELFFileAcceptsHashableBsignResult(t *testing.T) {
	fakeBsign(t, 0)

	path := filepath.Join(t.TempDir(), "binary")
	if err := os.WriteFile(path, []byte("payload"), 0o755); err != nil {
		t.Fatal(err)
	}

	if err := signELFFile(context.Background(), path, ELFSigningOptions{BsignEnabled: true}); err != nil {
		t.Fatal(err)
	}
}
