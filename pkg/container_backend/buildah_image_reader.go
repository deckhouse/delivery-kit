package container_backend

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/werf/logboek"
)

var _ ImageReader = (*buildahImageReader)(nil)

// buildahImageReader reads paths straight from a mounted throwaway container rootfs.
// The container is created and mounted once in OpenImageReader and torn down in Close.
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

func (r *buildahImageReader) ReadFile(ctx context.Context, path string) ([]byte, error) {
	data, err := os.ReadFile(filepath.Join(r.container.RootMount, path))
	if err != nil {
		return nil, fmt.Errorf("read %s from image %q: %w", path, r.imageRef, err)
	}
	return data, nil
}

func (r *buildahImageReader) ReadDir(ctx context.Context, path, destDir string, opts ReadDirOpts) error {
	srcRoot := filepath.Join(r.container.RootMount, path)
	if _, err := os.Stat(srcRoot); err != nil {
		return fmt.Errorf("read %s from image %q: %w", path, r.imageRef, err)
	}

	// The rootfs is a real filesystem here, so symlinks are followed by the OS; walk
	// through them so a pnpm-style node_modules/<pkg> link reads like it does in the image.
	return walkFollowingDirSymlinks(srcRoot, func(srcPath string, d fs.DirEntry) error {
		if !d.Type().IsRegular() || !matchesAnyFileNamePattern(d.Name(), opts.FileNamePatterns) {
			return nil
		}
		rel, err := filepath.Rel(srcRoot, srcPath)
		if err != nil {
			return fmt.Errorf("relativize %s: %w", srcPath, err)
		}
		destPath := filepath.Join(destDir, rel)
		if err := os.MkdirAll(filepath.Dir(destPath), 0o755); err != nil {
			return fmt.Errorf("create %s: %w", filepath.Dir(destPath), err)
		}
		data, err := os.ReadFile(srcPath)
		if err != nil {
			return fmt.Errorf("read %s from image %q: %w", srcPath, r.imageRef, err)
		}
		return os.WriteFile(destPath, data, 0o644)
	})
}

// walkFollowingDirSymlinks is filepath.WalkDir that descends into symlinked directories,
// guarding against cycles by tracking visited real paths.
func walkFollowingDirSymlinks(root string, fn func(path string, d fs.DirEntry) error) error {
	visited := map[string]struct{}{}

	var walk func(dir string) error
	walk = func(dir string) error {
		real, err := filepath.EvalSymlinks(dir)
		if err != nil {
			return nil
		}
		if _, seen := visited[real]; seen {
			return nil
		}
		visited[real] = struct{}{}

		entries, err := os.ReadDir(dir)
		if err != nil {
			return err
		}
		for _, d := range entries {
			path := filepath.Join(dir, d.Name())
			if d.Type()&fs.ModeSymlink != 0 {
				info, err := os.Stat(path)
				if err != nil || !info.IsDir() {
					continue
				}
				if err := walk(path); err != nil {
					return err
				}
				continue
			}
			if d.IsDir() {
				if err := walk(path); err != nil {
					return err
				}
				continue
			}
			if err := fn(path, d); err != nil {
				return err
			}
		}
		return nil
	}

	return walk(root)
}
