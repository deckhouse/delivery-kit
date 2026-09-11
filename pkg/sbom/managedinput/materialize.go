package managedinput

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/werf/logboek"
	"github.com/werf/werf/v2/pkg/container_backend"
	"github.com/werf/werf/v2/pkg/sbom/scanner"
)

// MaterializeCatalogerInputs extracts a cataloger's declared spec/lock files from the
// built image and writes them into a fresh temporary directory under their full in-image
// path, so a directory-source scan records the same locations the files had in the image
// (e.g. /app/api/go.mod) and keeps a spec next to its lock. Required inputs (SourcePaths)
// must be present — the build fails otherwise; optional inputs (OptionalSourcePaths, e.g. a
// go.sum a depless module never produces) are skipped when absent, matching the previous
// full-image scan. The returned directory and its files are world-readable so the
// unprivileged scanner container can read them. The caller must invoke the returned cleanup
// once the scan is done.
func MaterializeCatalogerInputs(ctx context.Context, backend container_backend.ContainerBackend, imageRef string, cataloger scanner.Cataloger, targetPlatform string) (string, func(context.Context), error) {
	dir, err := os.MkdirTemp("", "sbom-dirscan-*")
	if err != nil {
		return "", nil, fmt.Errorf("create scan dir: %w", err)
	}

	cleanup := func(ctx context.Context) {
		if err := os.RemoveAll(dir); err != nil {
			logboek.Context(ctx).Warn().LogF("WARNING: unable to remove scan dir %q: %s\n", dir, err)
		}
	}

	opts := container_backend.ReadFileFromImageOpts{TargetPlatform: targetPlatform}

	for _, sourcePath := range cataloger.SourcePaths {
		data, err := backend.ReadFileFromImage(ctx, imageRef, sourcePath, opts)
		if err != nil {
			cleanup(ctx)
			return "", nil, fmt.Errorf("read %s from image %q for cataloger %q: %w", sourcePath, imageRef, cataloger.Name, err)
		}
		if err := writeMaterializedFile(dir, sourcePath, data); err != nil {
			cleanup(ctx)
			return "", nil, err
		}
	}

	for _, sourcePath := range cataloger.OptionalSourcePaths {
		data, err := backend.ReadFileFromImage(ctx, imageRef, sourcePath, opts)
		if err != nil {
			logboek.Context(ctx).Debug().LogF("skip optional %s for cataloger %q: not present in image %q: %s\n", sourcePath, cataloger.Name, imageRef, err)
			continue
		}
		if err := writeMaterializedFile(dir, sourcePath, data); err != nil {
			cleanup(ctx)
			return "", nil, err
		}
	}

	// MkdirTemp, MkdirAll and WriteFile are all umask-subject, so under a restrictive umask
	// the scan root and its nested directories would not be traversable by the scanner
	// container's user. Force the whole tree world-readable (dirs also executable).
	if err := makeTreeWorldReadable(dir); err != nil {
		cleanup(ctx)
		return "", nil, fmt.Errorf("make scan dir %q world-readable: %w", dir, err)
	}

	return dir, cleanup, nil
}

func writeMaterializedFile(dir, sourcePath string, data []byte) error {
	// Rebase the in-image path onto the scan dir. Anchoring at "/" and cleaning first
	// collapses any ".." and leading slash, so the result can never escape dir.
	destPath := filepath.Join(dir, filepath.Clean("/"+sourcePath))
	if err := os.MkdirAll(filepath.Dir(destPath), 0o755); err != nil {
		return fmt.Errorf("create scan subdir for %s: %w", destPath, err)
	}
	if err := os.WriteFile(destPath, data, 0o644); err != nil {
		return fmt.Errorf("write %s: %w", destPath, err)
	}
	return nil
}

func makeTreeWorldReadable(root string) error {
	return filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		mode := fs.FileMode(0o644)
		if d.IsDir() {
			mode = 0o755
		}
		return os.Chmod(path, mode)
	})
}
