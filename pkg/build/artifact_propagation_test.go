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
