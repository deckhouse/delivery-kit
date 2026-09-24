package storage

import (
	"context"

	"github.com/werf/werf/v2/pkg/container_backend"
	"github.com/werf/werf/v2/pkg/image"
)

var _ container_backend.ContainerBackend = (*localImageListBackendStub)(nil)

type localImageListBackendStub struct {
	container_backend.ContainerBackend
	images  image.ImagesList
	err     error
	options container_backend.ImagesOptions
}

func (backend *localImageListBackendStub) Images(_ context.Context, options container_backend.ImagesOptions) (image.ImagesList, error) {
	backend.options = options
	return backend.images, backend.err
}
