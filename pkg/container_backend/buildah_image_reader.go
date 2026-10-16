package container_backend

import (
	"context"
	"fmt"
	"os"

	"github.com/werf/logboek"
)

func (backend *BuildahBackend) ReadFileFromImage(ctx context.Context, imageRef, path string, opts ReadFileFromImageOpts) ([]byte, error) {
	containers, err := backend.createContainers(ctx, []string{imageRef}, CommonOpts(opts))
	if err != nil {
		return nil, err
	}
	container := containers[0]
	defer func() {
		if err := backend.removeContainers(ctx, []*containerDesc{container}, CommonOpts(opts)); err != nil {
			logboek.Context(ctx).Error().LogF("ERROR: unable to remove temporal container %q: %s\n", container.Name, err)
		}
	}()

	if err := backend.mountContainers(ctx, []*containerDesc{container}, CommonOpts(opts)); err != nil {
		return nil, fmt.Errorf("mount container %q: %w", container.Name, err)
	}
	defer func() {
		if err := backend.unmountContainers(ctx, []*containerDesc{container}, CommonOpts(opts)); err != nil {
			logboek.Context(ctx).Error().LogF("ERROR: unable to unmount container %q: %s\n", container.Name, err)
		}
	}()

	data, err := readRegularFileFromRoot(container.RootMount, path)
	if err != nil {
		return nil, fmt.Errorf("read %s from image %q: %w", path, imageRef, err)
	}

	return data, nil
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

// OpenImageReader is intentionally unsupported on the Buildah backend: the only caller is
// the SBOM directory-scan flow, which rejects Buildah upfront (see the SBOM guard in the
// conveyor), so a ContainerBackend backed by Buildah never reaches an image reader.
func (backend *BuildahBackend) OpenImageReader(ctx context.Context, imageRef string, opts ReadFileFromImageOpts) (ImageReader, error) {
	return nil, fmt.Errorf("OpenImageReader is not supported with the Buildah backend")
}

// RunCommandInImage is unsupported on the Buildah backend for the same reason as
// OpenImageReader: its only caller is the SBOM flow, which rejects Buildah upfront.
func (backend *BuildahBackend) RunCommandInImage(ctx context.Context, imageRef string, opts RunCommandInImageOpts) ([]byte, error) {
	return nil, fmt.Errorf("RunCommandInImage is not supported with the Buildah backend")
}
