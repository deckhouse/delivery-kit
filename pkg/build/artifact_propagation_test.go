package build

import (
	"bytes"
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

	"github.com/werf/logboek"
	"github.com/werf/werf/v2/pkg/attestation"
	"github.com/werf/werf/v2/pkg/docker_registry"
	"github.com/werf/werf/v2/pkg/image"
	"github.com/werf/werf/v2/pkg/oci/artifact"
	"github.com/werf/werf/v2/pkg/storage"
	"github.com/werf/werf/v2/test/mock"
)

var _ = Describe("artifact propagation", func() {
	It("rejects an incomplete artifact source descriptor", func(ctx SpecContext) {
		err := ensureAttachedArtifacts(ctx, "", "")

		Expect(err).To(MatchError("artifact source descriptor is incomplete"))
	})

	It("rejects a nil source descriptor", func(ctx SpecContext) {
		err := propagateArtifacts(ctx, "project", "app", nil, nil, nil)

		Expect(err).To(MatchError("source image descriptor is unavailable"))
	})

	It("skips local-only artifact sources", func(ctx SpecContext) {
		err := propagateArtifacts(ctx, "project", "app", &image.StageDesc{
			Info: &image.Info{Repository: ":local", RepoDigest: ":local@sha256:local"},
		}, nil, nil)

		Expect(err).To(Succeed())
	})

	Describe("propagation errors", func() {
		var (
			server       *httptest.Server
			sourceRepo   string
			sourceDigest string
			remoteOpts   []remote.Option
		)

		stageDescFor := func(repo, digest string) *image.StageDesc {
			return &image.StageDesc{Info: &image.Info{
				Repository: repo,
				RepoDigest: repo + "@" + digest,
			}}
		}

		pushImageToRepo := func(ctx SpecContext, repo string) string {
			img, err := random.Image(256, 1)
			Expect(err).To(Succeed())
			ref, err := name.NewTag(repo + ":v1")
			Expect(err).To(Succeed())
			Expect(remote.Write(ref, img, append([]remote.Option{remote.WithContext(ctx)}, remoteOpts...)...)).To(Succeed())
			digest, err := img.Digest()
			Expect(err).To(Succeed())
			return digest.String()
		}

		BeforeEach(func(ctx SpecContext) {
			Expect(docker_registry.Init(ctx, false, false, nil, nil)).To(Succeed())

			server = httptest.NewServer(registry.New())
			host := strings.TrimPrefix(server.URL, "http://")
			sourceRepo = host + "/test/source"
			remoteOpts = []remote.Option{remote.WithAuth(authn.Anonymous)}

			img, err := random.Image(256, 1)
			Expect(err).To(Succeed())
			ref, err := name.NewTag(sourceRepo + ":v1")
			Expect(err).To(Succeed())
			Expect(remote.Write(ref, img, append([]remote.Option{remote.WithContext(ctx)}, remoteOpts...)...)).To(Succeed())
			digest, err := img.Digest()
			Expect(err).To(Succeed())
			sourceDigest = digest.String()

			store := artifact.NewOCIStore(sourceRepo, "app", remoteOpts...)
			Expect(store.Attach(ctx, sourceDigest, attestation.DSSEMediaType, []byte(`{"v":1}`), "checksum-v1", "", "")).To(Succeed())
		})

		AfterEach(func() {
			server.Close()
		})

		It("returns a final propagation error", func(ctx SpecContext) {
			err := propagateArtifacts(ctx, "project", "app", stageDescFor(sourceRepo, sourceDigest), stageDescFor("127.0.0.1:1/unreachable/final", sourceDigest), nil)

			Expect(err).To(MatchError(ContainSubstring("copy attached artifacts into final repo")))
		})

		It("propagates artifacts to final and cache repositories", func(ctx SpecContext) {
			finalRepo := strings.TrimPrefix(server.URL, "http://") + "/test/final"
			cacheRepo := strings.TrimPrefix(server.URL, "http://") + "/test/cache"
			finalDigest := pushImageToRepo(ctx, finalRepo)
			cacheDigest := pushImageToRepo(ctx, cacheRepo)
			cache := mock.NewMockStagesStorage(gomock.NewController(GinkgoT()))
			cache.EXPECT().Address().Return(cacheRepo).AnyTimes()
			cache.EXPECT().String().Return(cacheRepo).AnyTimes()
			cache.EXPECT().GetStageDesc(gomock.Any(), "project", image.StageID{Digest: "stage-digest"}).Return(stageDescFor(cacheRepo, cacheDigest), nil)

			source := stageDescFor(sourceRepo, sourceDigest)
			source.StageID = &image.StageID{Digest: "stage-digest"}
			err := propagateArtifacts(ctx, "project", "app", source, stageDescFor(finalRepo, finalDigest), []storage.StagesStorage{cache})
			Expect(err).To(Succeed())

			for _, destination := range []struct {
				repo   string
				digest string
			}{
				{repo: finalRepo, digest: finalDigest},
				{repo: cacheRepo, digest: cacheDigest},
			} {
				store := artifact.NewOCIStore(destination.repo, "app", remoteOpts...)
				content, err := store.GetAttachedContent(ctx, destination.digest, attestation.DSSEMediaType, nil)
				Expect(err).To(Succeed())
				Expect(content).To(MatchJSON(`{"v":1}`))
			}
		})

		It("resolves the cache destination digest before propagation", func(ctx SpecContext) {
			cacheRepo := strings.TrimPrefix(server.URL, "http://") + "/test/cache-digest"
			cacheDigest := pushImageToRepo(ctx, cacheRepo)
			cache := mock.NewMockStagesStorage(gomock.NewController(GinkgoT()))
			cache.EXPECT().Address().Return(cacheRepo).AnyTimes()
			cache.EXPECT().String().Return(cacheRepo).AnyTimes()
			cache.EXPECT().GetStageDesc(gomock.Any(), "project", gomock.Any()).Return(stageDescFor(cacheRepo, cacheDigest), nil)

			source := stageDescFor(sourceRepo, sourceDigest)
			source.StageID = &image.StageID{Digest: "stage-digest"}
			Expect(propagateArtifacts(ctx, "project", "app", source, nil, []storage.StagesStorage{cache})).To(Succeed())

			store := artifact.NewOCIStore(cacheRepo, "app", remoteOpts...)
			content, err := store.GetAttachedContent(ctx, cacheDigest, attestation.DSSEMediaType, nil)
			Expect(err).To(Succeed())
			Expect(content).To(MatchJSON(`{"v":1}`))
		})

		It("skips propagation when the destination repository is identical", func(ctx SpecContext) {
			destination := stageDescFor(sourceRepo, "sha256:does-not-exist")
			Expect(propagateArtifacts(ctx, "project", "app", stageDescFor(sourceRepo, sourceDigest), destination, nil)).To(Succeed())
		})

		It("deduplicates an artifact with the same identity", func(ctx SpecContext) {
			destinationRepo := strings.TrimPrefix(server.URL, "http://") + "/test/dedup"
			destinationDigest := pushImageToRepo(ctx, destinationRepo)
			destinationStore := artifact.NewOCIStore(destinationRepo, "app", remoteOpts...)
			Expect(destinationStore.Attach(ctx, destinationDigest, attestation.DSSEMediaType, []byte(`{"v":2}`), "checksum-v1", "", "")).To(Succeed())

			Expect(propagateArtifacts(ctx, "project", "app", stageDescFor(sourceRepo, sourceDigest), stageDescFor(destinationRepo, destinationDigest), nil)).To(Succeed())

			content, err := destinationStore.GetAttachedContent(ctx, destinationDigest, attestation.DSSEMediaType, nil)
			Expect(err).To(Succeed())
			Expect(content).To(MatchJSON(`{"v":2}`))
			index, err := artifact.PullFallbackIndex(ctx, destinationRepo, destinationDigest, remoteOpts...)
			Expect(err).To(Succeed())
			manifest, err := index.IndexManifest()
			Expect(err).To(Succeed())
			Expect(manifest.Manifests).To(HaveLen(1))
		})

		It("restores artifacts from a secondary repository onto the primary digest", func(ctx SpecContext) {
			primaryRepo := strings.TrimPrefix(server.URL, "http://") + "/test/primary"
			primaryDigest := pushImageToRepo(ctx, primaryRepo)
			source := stageDescFor(sourceRepo, sourceDigest)
			destination := stageDescFor(primaryRepo, primaryDigest)

			Expect(ensureAttachedArtifacts(ctx, source.Info.Repository, source.Info.GetDigest())).To(Succeed())
			Expect(propagateArtifacts(ctx, "project", "app", source, destination, nil)).To(Succeed())

			store := artifact.NewOCIStore(primaryRepo, "app", remoteOpts...)
			content, err := store.GetAttachedContent(ctx, primaryDigest, attestation.DSSEMediaType, nil)
			Expect(err).To(Succeed())
			Expect(content).To(MatchJSON(`{"v":1}`))
		})

		It("rejects a secondary source image without attached artifacts", func(ctx SpecContext) {
			repo := strings.TrimPrefix(server.URL, "http://") + "/test/missing-artifacts"
			digest := pushImageToRepo(ctx, repo)

			err := ensureAttachedArtifacts(ctx, repo, digest)
			Expect(err).To(MatchError(ContainSubstring("has no attached artifacts")))
		})

		It("logs cache propagation errors and continues", func(ctx SpecContext) {
			var output bytes.Buffer
			logCtx := logboek.NewContext(ctx, logboek.NewLogger(&output, &output))
			cache := mock.NewMockStagesStorage(gomock.NewController(GinkgoT()))
			cache.EXPECT().Address().Return("127.0.0.1:1/unreachable/cache").AnyTimes()
			cache.EXPECT().String().Return("127.0.0.1:1/unreachable/cache").AnyTimes()

			Expect(propagateArtifacts(logCtx, "", "app", stageDescFor(sourceRepo, sourceDigest), nil, []storage.StagesStorage{cache})).To(Succeed())
			Expect(output.String()).To(ContainSubstring("Warning: unable to copy artifacts into cache stages storage"))
		})
	})
})
