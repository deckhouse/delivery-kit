package contback

import (
	"fmt"
	"io"
	"sync/atomic"

	"github.com/opencontainers/go-digest"
	"go.podman.io/storage"
)

type cleanupTraceStore struct {
	storage.Store
	writer      io.Writer
	projectName string
	sequence    atomic.Uint64
}

var _ storage.Store = (*cleanupTraceStore)(nil)

func (store *cleanupTraceStore) trace(operation, details string) func(error) {
	phase := fmt.Sprintf("storage.%s call=%d%s", operation, store.sequence.Add(1), details)
	return traceBuildahCleanupPhase(store.writer, store.projectName, phase)
}

func (store *cleanupTraceStore) Image(ref string) (*storage.Image, error) {
	done := store.trace("Image", fmt.Sprintf(" ref=%q", ref))
	image, err := store.Store.Image(ref)
	done(err)
	return image, err
}

func (store *cleanupTraceStore) ImagesByDigest(imageDigest digest.Digest) ([]*storage.Image, error) {
	done := store.trace("ImagesByDigest", fmt.Sprintf(" digest=%q", imageDigest))
	images, err := store.Store.ImagesByDigest(imageDigest)
	done(err)
	return images, err
}

func (store *cleanupTraceStore) ImageBigData(id, key string) ([]byte, error) {
	done := store.trace("ImageBigData", fmt.Sprintf(" id=%q key=%q", id, key))
	data, err := store.Store.ImageBigData(id, key)
	done(err)
	return data, err
}

func (store *cleanupTraceStore) ListImageBigData(id string) ([]string, error) {
	done := store.trace("ListImageBigData", fmt.Sprintf(" id=%q", id))
	names, err := store.Store.ListImageBigData(id)
	done(err)
	return names, err
}

func (store *cleanupTraceStore) ImageBigDataSize(id, key string) (int64, error) {
	done := store.trace("ImageBigDataSize", fmt.Sprintf(" id=%q key=%q", id, key))
	size, err := store.Store.ImageBigDataSize(id, key)
	done(err)
	return size, err
}

func (store *cleanupTraceStore) LayersByUncompressedDigest(layerDigest digest.Digest) ([]storage.Layer, error) {
	done := store.trace("LayersByUncompressedDigest", fmt.Sprintf(" digest=%q", layerDigest))
	layers, err := store.Store.LayersByUncompressedDigest(layerDigest)
	done(err)
	return layers, err
}

func (store *cleanupTraceStore) Images() ([]storage.Image, error) {
	done := store.trace("Images", "")
	images, err := store.Store.Images()
	done(err)
	return images, err
}

func (store *cleanupTraceStore) Layers() ([]storage.Layer, error) {
	done := store.trace("Layers", "")
	layers, err := store.Store.Layers()
	done(err)
	return layers, err
}

func (store *cleanupTraceStore) Layer(id string) (*storage.Layer, error) {
	done := store.trace("Layer", fmt.Sprintf(" id=%q", id))
	layer, err := store.Store.Layer(id)
	done(err)
	return layer, err
}

func (store *cleanupTraceStore) MultiList(options storage.MultiListOptions) (storage.MultiListResult, error) {
	done := store.trace("MultiList", fmt.Sprintf(" images=%t layers=%t containers=%t", options.Images, options.Layers, options.Containers))
	result, err := store.Store.MultiList(options)
	done(err)
	return result, err
}

func (store *cleanupTraceStore) Containers() ([]storage.Container, error) {
	done := store.trace("Containers", "")
	containers, err := store.Store.Containers()
	done(err)
	return containers, err
}

func (store *cleanupTraceStore) RemoveNames(id string, names []string) error {
	done := store.trace("RemoveNames", fmt.Sprintf(" id=%q names=%q", id, names))
	err := store.Store.RemoveNames(id, names)
	done(err)
	return err
}

func (store *cleanupTraceStore) DeleteImage(id string, commit bool) ([]string, error) {
	done := store.trace("DeleteImage", fmt.Sprintf(" id=%q commit=%t", id, commit))
	layers, err := store.Store.DeleteImage(id, commit)
	done(err)
	return layers, err
}
