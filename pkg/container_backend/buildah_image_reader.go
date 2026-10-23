package container_backend

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"

	"github.com/bmatcuk/doublestar/v4"

	"github.com/werf/logboek"
)

func (backend *BuildahBackend) ReadFileFromImage(ctx context.Context, imageRef, path string, opts ReadFileFromImageOpts) ([]byte, error) {
	reader, err := backend.OpenImageReader(ctx, imageRef, opts)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err := reader.Close(ctx); err != nil {
			logboek.Context(ctx).Error().LogF("ERROR: %s\n", err)
		}
	}()

	return reader.ReadFile(ctx, path)
}

var _ ImageReader = (*buildahImageReader)(nil)

// buildahImageReader reads paths out of one container of the image, mounted once in
// OpenImageReader and released in Close.
type buildahImageReader struct {
	backend   *BuildahBackend
	imageRef  string
	container *containerDesc
	opts      CommonOpts
}

func (backend *BuildahBackend) OpenImageReader(ctx context.Context, imageRef string, opts ReadFileFromImageOpts) (ImageReader, error) {
	containers, err := backend.createContainers(ctx, []string{imageRef}, CommonOpts(opts))
	if err != nil {
		return nil, err
	}
	container := containers[0]

	if err := backend.mountContainers(ctx, []*containerDesc{container}, CommonOpts(opts)); err != nil {
		if rmErr := backend.removeContainers(ctx, []*containerDesc{container}, CommonOpts(opts)); rmErr != nil {
			logboek.Context(ctx).Error().LogF("ERROR: unable to remove temporal container %q: %s\n", container.Name, rmErr)
		}
		return nil, fmt.Errorf("mount container %q: %w", container.Name, err)
	}

	return &buildahImageReader{backend: backend, imageRef: imageRef, container: container, opts: CommonOpts(opts)}, nil
}

// Close removes the container even when unmounting it fails: the caller only logs the
// error, so this is the last chance to release the container.
func (r *buildahImageReader) Close(ctx context.Context) error {
	var errs []error
	if err := r.backend.unmountContainers(ctx, []*containerDesc{r.container}, r.opts); err != nil {
		errs = append(errs, fmt.Errorf("unmount container %q: %w", r.container.Name, err))
	}
	if err := r.backend.removeContainers(ctx, []*containerDesc{r.container}, r.opts); err != nil {
		errs = append(errs, fmt.Errorf("remove container %q: %w", r.container.Name, err))
	}
	return errors.Join(errs...)
}

func (r *buildahImageReader) ReadFile(_ context.Context, path string) ([]byte, error) {
	data, err := readRegularFileFromRoot(r.container.RootMount, path)
	if err != nil {
		return nil, fmt.Errorf("read %s from image %q: %w", path, r.imageRef, err)
	}
	return data, nil
}

// Glob walks the pattern's literal base directory inside the mounted root. The base is
// resolved against the container root, so a symlink there never leads to a host path;
// below it the walk does not descend into symlinks at all. A missing base is no match.
func (r *buildahImageReader) Glob(_ context.Context, pattern string) ([]string, error) {
	base, _ := doublestar.SplitPattern(pattern)
	resolvedBase, err := resolveContainerRootPath(r.container.RootMount, base)
	if err != nil {
		return nil, err
	}

	var matches []string
	err = filepath.WalkDir(resolvedBase, func(hostPath string, d fs.DirEntry, err error) error {
		if err != nil {
			if hostPath == resolvedBase && os.IsNotExist(err) {
				return filepath.SkipAll
			}
			return err
		}
		if !d.Type().IsRegular() {
			return nil
		}
		rel, err := filepath.Rel(resolvedBase, hostPath)
		if err != nil {
			return err
		}
		filePath := path.Join(base, filepath.ToSlash(rel))
		matched, err := doublestar.Match(pattern, filePath)
		if err != nil {
			return fmt.Errorf("match %s against %q: %w", filePath, pattern, err)
		}
		if matched {
			matches = append(matches, filePath)
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("glob %q in image %q: %w", pattern, r.imageRef, err)
	}
	sort.Strings(matches)
	return matches, nil
}

// ReadDir is intentionally unsupported on the Buildah backend: its only caller is the
// SBOM directory-scan flow, which rejects Buildah upfront (see the SBOM guard in the
// conveyor).
func (r *buildahImageReader) ReadDir(_ context.Context, _, _ string, _ ReadDirOpts) error {
	return fmt.Errorf("ReadDir is not supported with the Buildah backend")
}

// readRegularFileFromRoot reads path inside the mounted container root, following
// symlinks against that root rather than the host, and accepts regular files only,
// matching what the Docker reader yields for the same path.
func readRegularFileFromRoot(rootMount, path string) ([]byte, error) {
	resolvedPath, err := resolveContainerRootPath(rootMount, path)
	if err != nil {
		return nil, err
	}
	info, err := os.Lstat(resolvedPath)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("not a regular file")
	}
	return os.ReadFile(resolvedPath)
}

// RunCommandInImage is unsupported on the Buildah backend: its only caller is the SBOM
// flow, which rejects Buildah upfront.
func (backend *BuildahBackend) RunCommandInImage(ctx context.Context, imageRef string, opts RunCommandInImageOpts) ([]byte, error) {
	return nil, fmt.Errorf("RunCommandInImage is not supported with the Buildah backend")
}
