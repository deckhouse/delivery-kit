// Package webpackcollector delivers the private Webpack evidence collector into the
// stage that runs a UI build. The collector is this project's own JavaScript, so the
// werf binary that builds the stage carries it: a recipe asking for a checked Webpack
// build vendors no copy of it and pins no version of its own.
package webpackcollector

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"
)

// Extract writes the collector tree into directory and reports the SHA-256 of the
// uncompressed archive it came from. That digest names the collector a stage was
// instrumented with, so a werf carrying another one builds another stage.
func Extract(directory string) (string, error) {
	gzipData, expected, present := embeddedArchive()
	if !present {
		return "", fmt.Errorf("no-data: this werf carries no SBOM webpack collector")
	}
	digest := strings.TrimSpace(expected)
	packed, err := decompressAndVerify(gzipData, digest)
	if err != nil {
		return "", err
	}
	if err := unpack(packed, directory); err != nil {
		return "", err
	}

	return digest, nil
}

func decompressAndVerify(gzipData []byte, expectedSha256 string) ([]byte, error) {
	reader, err := gzip.NewReader(bytes.NewReader(gzipData))
	if err != nil {
		return nil, fmt.Errorf("init gzip reader for the embedded webpack collector: %w", err)
	}
	defer reader.Close()

	packed, err := io.ReadAll(reader)
	if err != nil {
		return nil, fmt.Errorf("decompress the embedded webpack collector: %w", err)
	}

	sum := sha256.Sum256(packed)
	if actual := hex.EncodeToString(sum[:]); actual != expectedSha256 {
		return nil, fmt.Errorf("embedded webpack collector integrity check failed: expected sha256 %s, got %s", expectedSha256, actual)
	}

	return packed, nil
}

// unpack writes every packed file under directory. The tree is mounted read-only into
// a build, so its modes are set explicitly rather than left to this process's umask:
// the user the stage runs its own commands as is not the user werf unpacked it as.
func unpack(packed []byte, directory string) error {
	if err := os.MkdirAll(directory, 0o755); err != nil {
		return err
	}
	archive := tar.NewReader(bytes.NewReader(packed))
	for {
		header, err := archive.Next()
		if err == io.EOF {
			return setModes(directory)
		}
		if err != nil {
			return fmt.Errorf("read the embedded webpack collector: %w", err)
		}
		if header.Typeflag != tar.TypeReg {
			return fmt.Errorf("embedded webpack collector holds %s, which is not an ordinary file", header.Name)
		}
		name := path.Clean(header.Name)
		if path.IsAbs(name) || name == ".." || strings.HasPrefix(name, "../") || name != header.Name {
			return fmt.Errorf("embedded webpack collector names %q, which is not a path inside the collector", header.Name)
		}
		file := filepath.Join(directory, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(file), 0o755); err != nil {
			return err
		}
		body, err := io.ReadAll(archive)
		if err != nil {
			return fmt.Errorf("read the embedded webpack collector: %w", err)
		}
		if err := os.WriteFile(file, body, 0o644); err != nil {
			return err
		}
	}
}

// setModes gives the unpacked tree the modes a build reads it through, whatever umask
// was in force while it was written.
func setModes(directory string) error {
	return filepath.WalkDir(directory, func(file string, item fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		mode := fs.FileMode(0o644)
		if item.IsDir() {
			mode = 0o755
		}

		return os.Chmod(file, mode)
	})
}
