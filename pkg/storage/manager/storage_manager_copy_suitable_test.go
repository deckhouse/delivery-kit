package manager

import (
	"context"
	"net/http/httptest"
	"strings"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/registry"
	"github.com/google/go-containerregistry/pkg/v1/random"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"go.uber.org/mock/gomock"

	"github.com/werf/werf/v3/pkg/attestation"
	"github.com/werf/werf/v3/pkg/container_backend"
	"github.com/werf/werf/v3/pkg/docker_registry"
	"github.com/werf/werf/v3/pkg/image"
	"github.com/werf/werf/v3/pkg/logging"
	"github.com/werf/werf/v3/pkg/oci/artifact"
	"github.com/werf/werf/v3/pkg/storage"
	"github.com/werf/werf/v3/pkg/werf"
	"github.com/werf/werf/v3/test/mock"
)

// copySuitableFakeStorage stands in for a registry-backed stages storage on the
// backend-mediated copy: it answers with the descriptor the stage has in its
// repository and accepts the fetch and the store without touching a backend.
type copySuitableFakeStorage struct {
	storage.PrimaryStagesStorage

	address string
	desc    *image.StageDesc
}

func (f *copySuitableFakeStorage) Address() string { return f.address }
func (f *copySuitableFakeStorage) String() string  { return f.address }

func (f *copySuitableFakeStorage) ConstructStageImageName(_, digest string, creationTs int64) string {
	return f.address + ":" + image.NewStageID(digest, creationTs).String()
}

func (f *copySuitableFakeStorage) FetchImage(_ context.Context, _ container_backend.LegacyImageInterface) error {
	return nil
}

func (f *copySuitableFakeStorage) StoreImage(_ context.Context, _ container_backend.LegacyImageInterface) error {
	return nil
}

func (f *copySuitableFakeStorage) GetStageDesc(_ context.Context, _ string, _ image.StageID) (*image.StageDesc, error) {
	return f.desc, nil
}

var _ = Describe("StorageManager.CopySuitableStageDescByDigest", func() {
	var (
		server     *httptest.Server
		srcRepo    string
		dstRepo    string
		remoteOpts []remote.Option
		stageID    *image.StageID
	)

	pushRandomImage := func(ctx SpecContext, repo string) string {
		img, err := random.Image(256, 1)
		Expect(err).To(Succeed())

		ref, err := name.NewTag(repo + ":v1")
		Expect(err).To(Succeed())
		Expect(remote.Write(ref, img, append([]remote.Option{remote.WithContext(ctx)}, remoteOpts...)...)).To(Succeed())

		dgst, err := img.Digest()
		Expect(err).To(Succeed())
		return dgst.String()
	}

	copyImageByDigest := func(ctx SpecContext, fromRepo, toRepo, digest string) {
		fromRef, err := name.NewDigest(fromRepo + "@" + digest)
		Expect(err).To(Succeed())
		img, err := remote.Image(fromRef, append([]remote.Option{remote.WithContext(ctx)}, remoteOpts...)...)
		Expect(err).To(Succeed())

		toRef, err := name.NewDigest(toRepo + "@" + digest)
		Expect(err).To(Succeed())
		Expect(remote.Write(toRef, img, append([]remote.Option{remote.WithContext(ctx)}, remoteOpts...)...)).To(Succeed())
	}

	stageDescIn := func(repo, digest string) *image.StageDesc {
		return &image.StageDesc{
			StageID: stageID,
			Info:    &image.Info{Name: repo + ":" + stageID.String(), Repository: repo, RepoDigest: repo + "@" + digest},
		}
	}

	newManager := func(dst *copySuitableFakeStorage) (*StorageManager, container_backend.ContainerBackend) {
		backend := mock.NewMockContainerBackend(gomock.NewController(GinkgoT()))
		backend.EXPECT().RenameImage(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(nil).AnyTimes()
		return &StorageManager{ProjectName: "project", StagesStorage: dst}, backend
	}

	attachedPayloads := func(ctx SpecContext, repo, digest string) []string {
		idx, err := artifact.PullFallbackIndex(ctx, repo, digest, remoteOpts...)
		Expect(err).To(Succeed())
		im, err := idx.IndexManifest()
		Expect(err).To(Succeed())

		var payloads []string
		for _, desc := range im.Manifests {
			payloads = append(payloads, desc.Annotations[artifact.PredicateTypeAnnotation]+"|"+desc.Annotations[image.WerfChecksumAnnotation])
		}
		return payloads
	}

	BeforeEach(func(ctx SpecContext) {
		Expect(werf.Init(GinkgoT().TempDir(), GinkgoT().TempDir())).To(Succeed())
		Expect(image.Init()).To(Succeed())
		Expect(docker_registry.Init(ctx, false, false, nil, nil)).To(Succeed())

		server = httptest.NewServer(registry.New())
		host := strings.TrimPrefix(server.URL, "http://")
		srcRepo = host + "/test/secondary"
		dstRepo = host + "/test/primary"
		remoteOpts = []remote.Option{remote.WithAuth(authn.Anonymous)}
		stageID = image.NewStageID("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", 1)
	})

	AfterEach(func() {
		server.Close()
	})

	It("carries the attached artifacts when the copy preserved the digest", func(ctx SpecContext) {
		digest := pushRandomImage(ctx, srcRepo)
		copyImageByDigest(ctx, srcRepo, dstRepo, digest)

		srcStore := artifact.NewOCIStore(srcRepo, "app", remoteOpts...)
		Expect(srcStore.Attach(ctx, digest, attestation.DSSEMediaType, []byte(`{"sbom":1}`), "checksum-sbom", "", "")).To(Succeed())

		src := &copySuitableFakeStorage{address: srcRepo}
		dst := &copySuitableFakeStorage{address: dstRepo, desc: stageDescIn(dstRepo, digest)}
		m, backend := newManager(dst)

		desc, err := m.CopySuitableStageDescByDigest(logging.WithLogger(ctx), stageDescIn(srcRepo, digest), src, dst, backend, "linux/amd64")
		Expect(err).NotTo(HaveOccurred())
		Expect(desc.Info.GetDigest()).To(Equal(digest))

		Expect(attachedPayloads(ctx, dstRepo, digest)).To(HaveLen(1))
	})

	It("carries nothing when the copy changed the digest", func(ctx SpecContext) {
		srcDigest := pushRandomImage(ctx, srcRepo)
		dstDigest := pushRandomImage(ctx, dstRepo)
		Expect(dstDigest).NotTo(Equal(srcDigest))

		srcStore := artifact.NewOCIStore(srcRepo, "app", remoteOpts...)
		Expect(srcStore.Attach(ctx, srcDigest, attestation.DSSEMediaType, []byte(`{"sbom":1}`), "checksum-sbom", "", "")).To(Succeed())
		Expect(srcStore.Attach(ctx, srcDigest, attestation.DSSEMediaType, []byte(`{"signed":1}`), "", "", "https://example.com/user-predicate")).To(Succeed())

		src := &copySuitableFakeStorage{address: srcRepo}
		dst := &copySuitableFakeStorage{address: dstRepo, desc: stageDescIn(dstRepo, dstDigest)}
		m, backend := newManager(dst)

		desc, err := m.CopySuitableStageDescByDigest(logging.WithLogger(ctx), stageDescIn(srcRepo, srcDigest), src, dst, backend, "linux/amd64")
		Expect(err).NotTo(HaveOccurred())
		Expect(desc.Info.GetDigest()).To(Equal(dstDigest))

		Expect(attachedPayloads(ctx, dstRepo, dstDigest)).To(BeEmpty(), "an artifact about %s must not be attached to %s", srcDigest, dstDigest)
		Expect(attachedPayloads(ctx, dstRepo, srcDigest)).To(BeEmpty())
		Expect(attachedPayloads(ctx, srcRepo, srcDigest)).To(HaveLen(2), "the source keeps what was left behind")
	})
})
