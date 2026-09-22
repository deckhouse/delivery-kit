//go:build unix

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
// exitCode when asked to check the ELF hash, and records both invocations.
func fakeBsign(t *testing.T, exitCode int) string {
	t.Helper()
	dir := t.TempDir()
	logPath := filepath.Join(dir, "calls")
	script := fmt.Sprintf(`#!/bin/sh
printf '%%s\n' "$*" >> "$BSIGN_TEST_LOG"
if [ "$1" = -cE ]; then
	echo 'bsign: invalid hash'
	exit %d
fi
exit 0
`, exitCode)
	if err := os.WriteFile(filepath.Join(dir, "bsign"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("BSIGN_TEST_LOG", logPath)
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	return logPath
}

func assertBsignCalls(t *testing.T, logPath, path string) {
	t.Helper()
	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	want := strings.Join([]string{
		"-N -s --pgoptions=--batch --default-key=TEST-FINGERPRINT " + path,
		"-cE " + path,
		"",
	}, "\n")
	if string(data) != want {
		t.Fatalf("bsign calls:\n%s\nwant:\n%s", data, want)
	}
}

func TestSignELFFileRejectsUnhashableBsignResult(t *testing.T) {
	for _, tc := range []struct {
		exitCode int
		message  string
	}{
		{66, "bad hash"},
		{64, "no hash"},
	} {
		t.Run(fmt.Sprint(tc.exitCode), func(t *testing.T) {
			logPath := fakeBsign(t, tc.exitCode)
			path := filepath.Join(t.TempDir(), "binary")
			if err := os.WriteFile(path, []byte("payload"), 0o755); err != nil {
				t.Fatal(err)
			}

			err := signELFFile(context.Background(), path, ELFSigningOptions{
				BsignEnabled:             true,
				PGPPrivateKeyFingerprint: "TEST-FINGERPRINT",
			})
			if err == nil {
				t.Fatal("signing accepted a file bsign cannot hash")
			}
			if !strings.Contains(err.Error(), "hash check") || !strings.Contains(err.Error(), tc.message) {
				t.Fatalf("unexpected error: %v", err)
			}
			assertBsignCalls(t, logPath, path)
		})
	}
}

// bsign reports a signature shorter than the section it reserves before it ever
// reaches the hash, for a sound file as much as for a corrupt one, so the check
// cannot decide either way and must not fail the build.
func TestSignELFFileAcceptsUncheckableHash(t *testing.T) {
	logPath := fakeBsign(t, 73)
	path := filepath.Join(t.TempDir(), "binary")
	if err := os.WriteFile(path, []byte("payload"), 0o755); err != nil {
		t.Fatal(err)
	}

	if err := signELFFile(context.Background(), path, ELFSigningOptions{
		BsignEnabled:             true,
		PGPPrivateKeyFingerprint: "TEST-FINGERPRINT",
	}); err != nil {
		t.Fatal(err)
	}
	assertBsignCalls(t, logPath, path)
}

func TestSignELFFileAcceptsHashableBsignResult(t *testing.T) {
	logPath := fakeBsign(t, 0)
	path := filepath.Join(t.TempDir(), "binary")
	if err := os.WriteFile(path, []byte("payload"), 0o755); err != nil {
		t.Fatal(err)
	}

	if err := signELFFile(context.Background(), path, ELFSigningOptions{
		BsignEnabled:             true,
		PGPPrivateKeyFingerprint: "TEST-FINGERPRINT",
	}); err != nil {
		t.Fatal(err)
	}
	assertBsignCalls(t, logPath, path)
}
