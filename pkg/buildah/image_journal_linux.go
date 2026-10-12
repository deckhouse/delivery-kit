package buildah

import (
	"context"
	"fmt"

	"github.com/opencontainers/go-digest"
	imgstor "go.podman.io/image/v5/storage"
	"go.podman.io/image/v5/types"
	"go.podman.io/storage"
	"go.podman.io/storage/pkg/stringid"

	"github.com/werf/werf/v3/pkg/image/journal"
)

type journalStore struct {
	storage.Store
	directory string
}

var _ storage.Store = (*journalStore)(nil)

func (store *journalStore) CreateImage(id string, names []string, layer, metadata string, options *storage.ImageOptions) (*storage.Image, error) {
	if id == "" {
		id = stringid.GenerateRandomID()
	}
	if err := journal.Record(context.Background(), store.directory, id); err != nil {
		return nil, fmt.Errorf("record created image: %w", err)
	}
	return store.Store.CreateImage(id, names, layer, metadata, options)
}

func (store *journalStore) Image(ref string) (*storage.Image, error) {
	image, err := store.Store.Image(ref)
	if err != nil {
		return nil, err
	}
	if err := journal.Record(context.Background(), store.directory, image.ID); err != nil {
		return nil, fmt.Errorf("record resolved image: %w", err)
	}
	return image, nil
}

func (store *journalStore) ImagesByDigest(imageDigest digest.Digest) ([]*storage.Image, error) {
	images, err := store.Store.ImagesByDigest(imageDigest)
	if err != nil {
		return nil, err
	}
	for _, image := range images {
		if err := journal.Record(context.Background(), store.directory, image.ID); err != nil {
			return nil, fmt.Errorf("record digest image: %w", err)
		}
	}
	return images, nil
}

type journalTransport struct {
	imgstor.StoreTransport
}

var _ imgstor.StoreTransport = (*journalTransport)(nil)

func (transport *journalTransport) ParseReference(value string) (types.ImageReference, error) {
	ref, err := transport.StoreTransport.ParseReference(value)
	if err != nil {
		return nil, err
	}
	store, tracked := transport.GetStoreIfSet().(*journalStore)
	if !tracked {
		return ref, nil
	}
	resolvedTransport, ok := ref.Transport().(imgstor.StoreTransport)
	if !ok {
		return nil, fmt.Errorf("unexpected storage reference transport")
	}
	resolvedStore := resolvedTransport.GetStoreIfSet()
	if resolvedStore == nil || resolvedStore.GraphRoot() != store.GraphRoot() || resolvedStore.RunRoot() != store.RunRoot() || resolvedStore.GraphDriverName() != store.GraphDriverName() {
		return nil, fmt.Errorf("image journaling does not support references to another storage")
	}
	return transport.ParseStoreReference(store, ref.StringWithinTransport())
}
