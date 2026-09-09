package managedinput

import (
	"context"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/werf/logboek"
	"github.com/werf/werf/v2/pkg/container_backend"
	"github.com/werf/werf/v2/pkg/sbom/scanner"
)

// MaterializeCatalogerInputs extracts a cataloger's declared spec/lock files from the
// built image and writes them into a fresh temporary directory, preserving their layout
// relative to the directive workdir so that syft's directory-source catalogers can link
// a spec to its lock (e.g. go.mod next to go.sum). The returned directory and its files
// are world-readable so the unprivileged scanner container can read them. The caller must
// invoke the returned cleanup once the scan is done.
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

		destPath := filepath.Join(dir, relativeToWorkdir(sourcePath, cataloger.Workdir))
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

// relativeToWorkdir maps an in-image absolute path to its path relative to the directive
// workdir, so a materialized file keeps the position the cataloger expects. Paths outside
// the workdir fall back to their base name.
func relativeToWorkdir(sourcePath, workdir string) string {
	workdir = strings.TrimSuffix(workdir, "/")
	if workdir != "" && strings.HasPrefix(sourcePath, workdir+"/") {
		return strings.TrimPrefix(sourcePath, workdir+"/")
	}
	return path.Base(sourcePath)
}
