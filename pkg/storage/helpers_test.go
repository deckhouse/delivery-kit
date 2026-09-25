package storage

import (
	"context"
	"fmt"
	"net/http/httptest"
	"strings"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/registry"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/remote/transport"
	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"

	"github.com/werf/werf/v3/pkg/container_backend"
	"github.com/werf/werf/v3/pkg/docker_registry"
	"github.com/werf/werf/v3/pkg/image"
)

func startLocalRegistry(ctx context.Context) string {
	gomega.Expect(docker_registry.Init(ctx, true, false, []string{}, []string{})).To(gomega.Succeed())
	server := httptest.NewServer(registry.New())
	ginkgo.DeferCleanup(server.Close)
	return strings.TrimPrefix(server.URL, "http://")
}

func putWithDigest(r *markerRegistry, reference, repoDigest string) {
	r.put(reference, nil)
	r.mu.Lock()
	defer r.mu.Unlock()
	r.images[reference].RepoDigest = repoDigest
}

var _ docker_registry.Interface = (*metadataPushRegistry)(nil)

type metadataPushRegistry struct {
	*pushImageRegistryStub
}

func (r *metadataPushRegistry) Tags(_ context.Context, _ string, _ ...docker_registry.Option) ([]string, error) {
	return nil, fmt.Errorf("tag listing must not be needed to publish metadata")
}

var _ docker_registry.Interface = (*stageLookupRegistry)(nil)

type stageLookupRegistry struct {
	*markerRegistry
	brokenImage *image.Info
	realCopy    bool
}

func (r *stageLookupRegistry) CopyImage(ctx context.Context, sourceReference, destinationReference string, opts docker_registry.CopyImageOptions) error {
	if err := r.markerRegistry.CopyImage(ctx, sourceReference, destinationReference, opts); err != nil {
		return err
	}
	if !r.realCopy {
		return nil
	}

	sourceRef, err := name.NewTag(sourceReference)
	if err != nil {
		return err
	}
	destinationRef, err := name.NewTag(destinationReference)
	if err != nil {
		return err
	}
	img, err := remote.Image(sourceRef, remote.WithContext(ctx))
	if err != nil {
		return err
	}
	if err := remote.Write(destinationRef, img, remote.WithContext(ctx)); err != nil {
		return err
	}
	digest, err := img.Digest()
	if err != nil {
		return err
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	r.images[destinationReference].RepoDigest = refRepo(destinationReference) + "@" + digest.String()
	return nil
}

func (r *stageLookupRegistry) GetRepoImage(ctx context.Context, reference string) (*image.Info, error) {
	info, err := r.markerRegistry.GetRepoImage(ctx, reference)
	if err != nil {
		return nil, err
	}
	if info == nil {
		return nil, fmt.Errorf("%s: %s", transport.ManifestUnknownErrorCode, reference)
	}
	if info == r.brokenImage {
		return nil, fmt.Errorf("%s: %s", transport.BlobUnknownErrorCode, reference)
	}
	return info, nil
}

var _ container_backend.ContainerBackend = (*stageLookupBackend)(nil)

type stageLookupBackend struct {
	container_backend.ContainerBackend
	info *image.Info
}

func (b *stageLookupBackend) GetImageInfo(_ context.Context, _ string, _ container_backend.GetImageInfoOpts) (*image.Info, error) {
	return b.info, nil
}

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
