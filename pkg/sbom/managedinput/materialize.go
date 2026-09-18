package managedinput

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/werf/logboek"
	"github.com/werf/werf/v2/pkg/container_backend"
	"github.com/werf/werf/v2/pkg/sbom/scanner"
)

// MaterializeCatalogerInputs extracts a cataloger's declared spec/lock files from the
// built image and writes them under their full in-image path into a scan directory, so a
// directory-source scan records the same locations the files had in the image (e.g.
// /app/api/go.mod) and keeps a spec next to its lock. Required inputs (SourcePaths) must
// be present — the build fails otherwise; optional inputs (OptionalSourcePaths, e.g. a
// go.sum a depless module never produces) are skipped only when genuinely absent from the
// image, any other read failure aborts.
//
// The returned scan directory is world-readable so the scanner container's user can read
// it, but it sits inside a 0700 parent owned by the invoking user: on a shared host other
// users cannot enumerate or read the extracted manifests. Bind-mount only the returned
// directory. The caller must invoke the returned cleanup once the scan is done.
func MaterializeCatalogerInputs(ctx context.Context, backend container_backend.ContainerBackend, imageRef string, cataloger scanner.Cataloger, targetPlatform string) (string, func(context.Context), error) {
	parentDir, err := os.MkdirTemp("", "sbom-dirscan-*")
	if err != nil {
		return "", nil, fmt.Errorf("create scan parent dir: %w", err)
	}

	cleanup := func(ctx context.Context) {
		if err := os.RemoveAll(parentDir); err != nil {
			logboek.Context(ctx).Warn().LogF("WARNING: unable to remove scan dir %q: %s\n", parentDir, err)
		}
	}

	// MkdirTemp is umask-subject; pin the parent to owner-only regardless of umask.
	if err := os.Chmod(parentDir, 0o700); err != nil {
		cleanup(ctx)
		return "", nil, fmt.Errorf("restrict scan parent dir %q: %w", parentDir, err)
	}

	scanDir := filepath.Join(parentDir, "scan")
	if err := os.Mkdir(scanDir, 0o755); err != nil {
		cleanup(ctx)
		return "", nil, fmt.Errorf("create scan dir %q: %w", scanDir, err)
	}

	opts := container_backend.ReadFileFromImageOpts{TargetPlatform: targetPlatform}

	for _, sourcePath := range cataloger.SourcePaths {
		data, err := backend.ReadFileFromImage(ctx, imageRef, sourcePath, opts)
		if err != nil {
			cleanup(ctx)
			return "", nil, fmt.Errorf("read %s from image %q for cataloger %q: %w", sourcePath, imageRef, cataloger.Name, err)
		}
		if err := writeMaterializedFile(scanDir, sourcePath, data); err != nil {
			cleanup(ctx)
			return "", nil, err
		}
	}

	for _, sourcePath := range cataloger.OptionalSourcePaths {
		data, err := backend.ReadFileFromImage(ctx, imageRef, sourcePath, opts)
		if errors.Is(err, fs.ErrNotExist) {
			logboek.Context(ctx).Warn().LogF("WARNING: lock file %s not found in image %q for cataloger %q; scanning the spec only. This is expected for a project without dependencies; otherwise transitive dependencies will be missing from the SBOM\n", sourcePath, imageRef, cataloger.Name)
			continue
		}
		if err != nil {
			cleanup(ctx)
			return "", nil, fmt.Errorf("read %s from image %q for cataloger %q: %w", sourcePath, imageRef, cataloger.Name, err)
		}
		if err := writeMaterializedFile(scanDir, sourcePath, data); err != nil {
			cleanup(ctx)
			return "", nil, err
		}
	}

	// Mkdir, MkdirAll and WriteFile are all umask-subject, so under a restrictive umask
	// the scan dir and its nested directories would not be traversable by the scanner
	// container's user. Force the scan subtree world-readable (dirs also executable);
	// the 0700 parent above keeps it private to the invoking user on the host.
	if err := makeTreeWorldReadable(scanDir); err != nil {
		cleanup(ctx)
		return "", nil, fmt.Errorf("make scan dir %q world-readable: %w", scanDir, err)
	}

	return scanDir, cleanup, nil
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
