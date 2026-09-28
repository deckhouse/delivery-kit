package container_backend

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

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

	data, err := os.ReadFile(filepath.Join(container.RootMount, path))
	if err != nil {
		return nil, fmt.Errorf("read %s from image %q: %w", path, imageRef, err)
	}

	return data, nil
}

// OpenImageReader is intentionally unsupported on the Buildah backend: the only caller is
// the SBOM directory-scan flow, which rejects Buildah upfront (see the SBOM guard in the
// conveyor), so a ContainerBackend backed by Buildah never reaches an image reader.
func (backend *BuildahBackend) OpenImageReader(ctx context.Context, imageRef string, opts ReadFileFromImageOpts) (ImageReader, error) {
	return nil, fmt.Errorf("OpenImageReader is not supported with the Buildah backend")
}
