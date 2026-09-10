package managedinput

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/werf/logboek"
	"github.com/werf/werf/v2/pkg/container_backend"
	"github.com/werf/werf/v2/pkg/sbom/scanner"
)

// MaterializeCatalogerInputs extracts a cataloger's declared spec/lock files from the
// built image and writes them into a fresh temporary directory under their full in-image
// path, so a directory-source scan records the same locations the files had in the image
// (e.g. /app/api/go.mod) and keeps a spec next to its lock. The returned directory and
// its files are world-readable so the unprivileged scanner container can read them. The
// caller must invoke the returned cleanup once the scan is done.
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

	if err := os.Chmod(dir, 0o755); err != nil {
		cleanup(ctx)
		return "", nil, fmt.Errorf("chmod scan dir %q: %w", dir, err)
	}

	for _, sourcePath := range cataloger.SourcePaths {
		data, err := backend.ReadFileFromImage(ctx, imageRef, sourcePath, container_backend.ReadFileFromImageOpts{TargetPlatform: targetPlatform})
		if err != nil {
			cleanup(ctx)
			return "", nil, fmt.Errorf("read %s from image %q for cataloger %q: %w", sourcePath, imageRef, cataloger.Name, err)
		}

		// Rebase the in-image path onto the scan dir. Anchoring at "/" and cleaning first
		// collapses any ".." and leading slash, so the result can never escape dir.
		destPath := filepath.Join(dir, filepath.Clean("/"+sourcePath))
		if err := os.MkdirAll(filepath.Dir(destPath), 0o755); err != nil {
			cleanup(ctx)
			return "", nil, fmt.Errorf("create scan subdir for %s: %w", destPath, err)
		}
		if err := os.WriteFile(destPath, data, 0o644); err != nil {
			cleanup(ctx)
			return "", nil, fmt.Errorf("write %s: %w", destPath, err)
		}
		if err := os.Chmod(destPath, 0o644); err != nil {
			cleanup(ctx)
			return "", nil, fmt.Errorf("chmod %s: %w", destPath, err)
		}
	}

	return dir, cleanup, nil
}
