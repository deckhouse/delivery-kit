package build

import (
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

	"github.com/werf/werf/v2/pkg/attestation"
	"github.com/werf/werf/v2/pkg/docker_registry"
	werfImage "github.com/werf/werf/v2/pkg/image"
	"github.com/werf/werf/v2/pkg/oci/artifact"
	"github.com/werf/werf/v2/pkg/storage"
	"github.com/werf/werf/v2/test/mock"
)

var _ = Describe("SbomStep PropagateArtifacts", func() {
	var (
		server     *httptest.Server
		srcRepo    string
		finalRepo  string
		cacheRepo  string
		srcDigest  string
		remoteOpts []remote.Option
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

	stageDescFor := func(repo, digest string) *werfImage.StageDesc {
		return &werfImage.StageDesc{
			StageID: &werfImage.StageID{},
			Info: &werfImage.Info{
				Repository: repo,
				RepoDigest: repo + "@" + digest,
			},
		}
	}

	cacheStorage := func(address string) *mock.MockStagesStorage {
		s := mock.NewMockStagesStorage(gomock.NewController(GinkgoT()))
		s.EXPECT().Address().Return(address).AnyTimes()
		s.EXPECT().String().Return(address).AnyTimes()
		return s
	}

	BeforeEach(func(ctx SpecContext) {
		Expect(docker_registry.Init(ctx, false, false, nil, nil)).To(Succeed())

		server = httptest.NewServer(registry.New())
		host := strings.TrimPrefix(server.URL, "http://")
		srcRepo = host + "/test/stages"
		finalRepo = host + "/test/final"
		cacheRepo = host + "/test/cache"
		remoteOpts = []remote.Option{remote.WithAuth(authn.Anonymous)}

		srcDigest = pushRandomImage(ctx, srcRepo)

		srcStore := artifact.NewOCIStore(srcRepo, "app", remoteOpts...)
		Expect(srcStore.Attach(ctx, srcDigest, attestation.DSSEMediaType, []byte(`{"v":1}`), "checksum-v1", "", "")).To(Succeed())
	})

	AfterEach(func() {
		server.Close()
	})

	It("should copy the SBOM into the final repo", func(ctx SpecContext) {
		copyImageByDigest(ctx, srcRepo, finalRepo, srcDigest)

		step := &sbomStep{}
		source := stageDescFor(srcRepo, srcDigest)
		destination := stageDescFor(finalRepo, srcDigest)
		Expect(step.PropagateArtifacts(ctx, "test", "app", source, destination, nil)).To(Succeed())
		Expect(step.PropagateArtifacts(ctx, "test", "app", source, destination, nil)).To(Succeed())

		finalStore := artifact.NewOCIStore(finalRepo, "app", remoteOpts...)
		content, err := finalStore.GetAttachedContent(ctx, srcDigest, attestation.DSSEMediaType, nil)
		Expect(err).To(Succeed())
		Expect(content).To(MatchJSON(`{"v":1}`))

		index, err := artifact.PullFallbackIndex(ctx, finalRepo, srcDigest, remoteOpts...)
		Expect(err).To(Succeed())
		manifest, err := index.IndexManifest()
		Expect(err).To(Succeed())
		Expect(manifest.Manifests).To(HaveLen(1))
	})

	It("should copy the SBOM into cache repos", func(ctx SpecContext) {
		copyImageByDigest(ctx, srcRepo, cacheRepo, srcDigest)

		step := &sbomStep{}
		caches := []storage.StagesStorage{
			cacheStorage(storage.LocalStorageAddress),
			cacheStorage(srcRepo),
			cacheStorage(cacheRepo),
		}
		Expect(step.PropagateArtifacts(ctx, "test", "app", stageDescFor(srcRepo, srcDigest), nil, caches)).To(Succeed())

		cacheStore := artifact.NewOCIStore(cacheRepo, "app", remoteOpts...)
		content, err := cacheStore.GetAttachedContent(ctx, srcDigest, attestation.DSSEMediaType, nil)
		Expect(err).To(Succeed())
		Expect(content).To(MatchJSON(`{"v":1}`))
	})

	It("should propagate artifacts to the cache image digest", func(ctx SpecContext) {
		destinationDigest := pushRandomImage(ctx, cacheRepo)
		cache := cacheStorage(cacheRepo)
		cache.EXPECT().GetStageDesc(gomock.Any(), "test", werfImage.StageID{Digest: "stage-digest"}).Return(&werfImage.StageDesc{
			StageID: &werfImage.StageID{Digest: "stage-digest"},
			Info: &werfImage.Info{
				Repository: cacheRepo,
				RepoDigest: cacheRepo + "@" + destinationDigest,
			},
		}, nil)

		step := &sbomStep{}
		source := stageDescFor(srcRepo, srcDigest)
		source.StageID = &werfImage.StageID{Digest: "stage-digest"}
		Expect(step.PropagateArtifacts(ctx, "test", "app", source, nil, []storage.StagesStorage{cache})).To(Succeed())

		cacheStore := artifact.NewOCIStore(cacheRepo, "app", remoteOpts...)
		content, err := cacheStore.GetAttachedContent(ctx, destinationDigest, attestation.DSSEMediaType, nil)
		Expect(err).To(Succeed())
		Expect(content).To(MatchJSON(`{"v":1}`))
	})

	It("should do nothing without a final repo and caches", func(ctx SpecContext) {
		step := &sbomStep{}
		Expect(step.PropagateArtifacts(ctx, "test", "app", stageDescFor(srcRepo, srcDigest), nil, nil)).To(Succeed())
	})

	It("should skip the final repo when it matches the stages repo", func(ctx SpecContext) {
		step := &sbomStep{}
		Expect(step.PropagateArtifacts(ctx, "test", "app", stageDescFor(srcRepo, srcDigest), stageDescFor(srcRepo, srcDigest), nil)).To(Succeed())
	})

	It("should not fail when a cache repo is unreachable", func(ctx SpecContext) {
		step := &sbomStep{}
		caches := []storage.StagesStorage{cacheStorage("127.0.0.1:1/unreachable/cache")}
		Expect(step.PropagateArtifacts(ctx, "test", "app", stageDescFor(srcRepo, srcDigest), nil, caches)).To(Succeed())
	})

	It("should fail when the final repo copy fails", func(ctx SpecContext) {
		step := &sbomStep{}
		err := step.PropagateArtifacts(ctx, "test", "app", stageDescFor(srcRepo, srcDigest), stageDescFor("127.0.0.1:1/unreachable/final", srcDigest), nil)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("copy attached artifacts into final repo"))
	})
})
