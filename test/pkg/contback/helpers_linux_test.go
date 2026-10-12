package contback

import (
	"bytes"
	"encoding/json"
	"io"
	"sync"

	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"
	"github.com/opencontainers/go-digest"
	"github.com/opencontainers/image-spec/specs-go"
	v1 "github.com/opencontainers/image-spec/specs-go/v1"
	"go.podman.io/storage"
)

type cleanupTraceObserver struct {
	output  bytes.Buffer
	marker  string
	started chan struct{}
	once    sync.Once
}

var _ io.Writer = (*cleanupTraceObserver)(nil)

func (observer *cleanupTraceObserver) Write(data []byte) (int, error) {
	count, err := observer.output.Write(data)
	if bytes.Contains(observer.output.Bytes(), []byte(observer.marker)) {
		observer.once.Do(func() { close(observer.started) })
	}
	return count, err
}

type cleanupInventoryStore struct {
	storage.Store
	listings int
}

var _ storage.Store = (*cleanupInventoryStore)(nil)

func (store *cleanupInventoryStore) MultiList(options storage.MultiListOptions) (storage.MultiListResult, error) {
	if options.Images && !options.Layers && !options.Containers {
		store.listings++
	}
	return store.Store.MultiList(options)
}

type cleanupLookupStore struct {
	storage.Store
	lookups      []string
	lookupError  error
	beforeLookup func() error
}

var _ storage.Store = (*cleanupLookupStore)(nil)

func (store *cleanupLookupStore) Image(id string) (*storage.Image, error) {
	store.lookups = append(store.lookups, id)
	if store.beforeLookup != nil {
		callback := store.beforeLookup
		store.beforeLookup = nil
		if err := callback(); err != nil {
			return nil, err
		}
	}
	if store.lookupError != nil {
		return nil, store.lookupError
	}
	return store.Store.Image(id)
}

func createCleanupImage(store storage.Store, project, fixture string, names []string) string {
	ginkgo.GinkgoHelper()
	config, err := json.Marshal(v1.Image{
		Platform: v1.Platform{Architecture: "amd64", OS: "linux"},
		Config:   v1.ImageConfig{Labels: map[string]string{"werf": project, "fixture": fixture}},
		RootFS:   v1.RootFS{Type: "layers", DiffIDs: []digest.Digest{}},
	})
	gomega.Expect(err).NotTo(gomega.HaveOccurred())
	configDigest := digest.FromBytes(config)
	manifest, err := json.Marshal(v1.Manifest{
		Versioned: specs.Versioned{SchemaVersion: 2},
		MediaType: v1.MediaTypeImageManifest,
		Config:    v1.Descriptor{MediaType: v1.MediaTypeImageConfig, Digest: configDigest, Size: int64(len(config))},
		Layers:    []v1.Descriptor{},
	})
	gomega.Expect(err).NotTo(gomega.HaveOccurred())
	image, err := store.CreateImage(configDigest.Encoded(), names, "", "", &storage.ImageOptions{})
	gomega.Expect(err).NotTo(gomega.HaveOccurred())
	digestData := func(data []byte) (digest.Digest, error) { return digest.FromBytes(data), nil }
	gomega.Expect(store.SetImageBigData(image.ID, configDigest.String(), config, digestData)).To(gomega.Succeed())
	gomega.Expect(store.SetImageBigData(image.ID, storage.ImageDigestBigDataKey, manifest, digestData)).To(gomega.Succeed())
	return image.ID
}
