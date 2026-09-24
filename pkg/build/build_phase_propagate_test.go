package build

import (
	"net/http/httptest"
	"strings"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/registry"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/random"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"go.uber.org/mock/gomock"

	"github.com/werf/werf/v3/pkg/attestation"
	"github.com/werf/werf/v3/pkg/build/image"
	"github.com/werf/werf/v3/pkg/docker_registry"
	imagePkg "github.com/werf/werf/v3/pkg/image"
	"github.com/werf/werf/v3/pkg/oci/artifact"
	"github.com/werf/werf/v3/pkg/storage"
	"github.com/werf/werf/v3/pkg/storage/manager"
	"github.com/werf/werf/v3/test/mock"
)

var _ = Describe("BuildPhase propagateArtifacts", func() {
	var (
		server     *httptest.Server
		stagesRepo string
		finalRepo  string
		cacheRepo  string
		remoteOpts []remote.Option
	)

	pushImage := func(ctx SpecContext, repo, tag string) string {
		img, err := random.Image(256, 1)
		Expect(err).To(Succeed())

		ref, err := name.NewTag(repo + ":" + tag)
		Expect(err).To(Succeed())
		Expect(remote.Write(ref, img, append([]remote.Option{remote.WithContext(ctx)}, remoteOpts...)...)).To(Succeed())

		dgst, err := img.Digest()
		Expect(err).To(Succeed())
		return dgst.String()
	}

	pushIndex := func(ctx SpecContext, repo, tag string, platforms []string) (string, []string) {
		idx := v1.ImageIndex(empty.Index)
		var children []string

		for _, platform := range platforms {
			img, err := random.Image(256, 1)
			Expect(err).To(Succeed())

			parsed, err := v1.ParsePlatform(platform)
			Expect(err).To(Succeed())

			idx = mutate.AppendManifests(idx, mutate.IndexAddendum{Add: img, Descriptor: v1.Descriptor{Platform: parsed}})

			dgst, err := img.Digest()
			Expect(err).To(Succeed())
			children = append(children, dgst.String())
		}

		ref, err := name.NewTag(repo + ":" + tag)
		Expect(err).To(Succeed())
		Expect(remote.WriteIndex(ref, idx, append([]remote.Option{remote.WithContext(ctx)}, remoteOpts...)...)).To(Succeed())

		dgst, err := idx.Digest()
		Expect(err).To(Succeed())
		return dgst.String(), children
	}

	copyManifestByDigest := func(ctx SpecContext, fromRepo, toRepo, digest string) {
		fromRef, err := name.NewDigest(fromRepo + "@" + digest)
		Expect(err).To(Succeed())
		desc, err := remote.Get(fromRef, append([]remote.Option{remote.WithContext(ctx)}, remoteOpts...)...)
		Expect(err).To(Succeed())

		toRef, err := name.NewDigest(toRepo + "@" + digest)
		Expect(err).To(Succeed())

		if desc.MediaType.IsIndex() {
			idx, err := desc.ImageIndex()
			Expect(err).To(Succeed())
			Expect(remote.WriteIndex(toRef, idx, append([]remote.Option{remote.WithContext(ctx)}, remoteOpts...)...)).To(Succeed())
			return
		}

		img, err := desc.Image()
		Expect(err).To(Succeed())
		Expect(remote.Write(toRef, img, append([]remote.Option{remote.WithContext(ctx)}, remoteOpts...)...)).To(Succeed())
	}

	attach := func(ctx SpecContext, repo, digest, payload string) {
		store := artifact.NewOCIStore(repo, "app", remoteOpts...)
		Expect(store.Attach(ctx, digest, attestation.DSSEMediaType, []byte(payload), "checksum-"+payload, "", "")).To(Succeed())
	}

	expectAttached := func(ctx SpecContext, repo, digest, payload string) {
		store := artifact.NewOCIStore(repo, "app", remoteOpts...)
		content, err := store.GetAttachedContent(ctx, digest, attestation.DSSEMediaType, nil)
		Expect(err).To(Succeed(), "no artifact attached to %s in %s", digest, repo)
		Expect(content).To(MatchJSON(payload))
	}

	expectNothingAttached := func(ctx SpecContext, repo, digest string) {
		idx, err := artifact.PullFallbackIndex(ctx, repo, digest, remoteOpts...)
		Expect(err).To(Succeed())
		im, err := idx.IndexManifest()
		Expect(err).To(Succeed())
		Expect(im.Manifests).To(BeEmpty(), "unexpected artifact attached to %s in %s", digest, repo)
	}

	newPhase := func(tree *image.ImagesTree, cacheStorages ...storage.StagesStorage) *BuildPhase {
		storageManager := &manager.StorageManager{
			StagesStorage:          storage.NewRepoStagesStorage(&storage.NewRepoStagesStorageOptions{RepoAddress: stagesRepo}),
			CacheStagesStorageList: cacheStorages,
		}
		return &BuildPhase{
			BasePhase: BasePhase{Conveyor: &Conveyor{imagesTree: tree, StorageManager: storageManager}},
			sbomStep:  &sbomStep{},
		}
	}

	newImage := func(ctx SpecContext, platform, repo, digest string, final *imagePkg.StageDesc) *image.Image {
		img, err := image.NewImage(ctx, platform, "app", image.NoBaseImage, image.ImageOptions{})
		Expect(err).To(Succeed())

		img.SetContentTagDesc(&imagePkg.StageDesc{
			StageID: imagePkg.NewStageID("digest", 1),
			Info:    &imagePkg.Info{Repository: repo, RepoDigest: repo + "@" + digest},
		})
		if final != nil {
			img.SetFinalContentTagDesc(final)
		}
		return img
	}

	cacheStorage := func(address string) storage.StagesStorage {
		s := mock.NewMockStagesStorage(gomock.NewController(GinkgoT()))
		s.EXPECT().Address().Return(address).AnyTimes()
		s.EXPECT().String().Return(address).AnyTimes()
		return s
	}

	BeforeEach(func(ctx SpecContext) {
		Expect(docker_registry.Init(ctx, false, false, nil, nil)).To(Succeed())

		server = httptest.NewServer(registry.New())
		host := strings.TrimPrefix(server.URL, "http://")
		stagesRepo = host + "/test/stages"
		finalRepo = host + "/test/final"
		cacheRepo = host + "/test/cache"
		remoteOpts = []remote.Option{remote.WithAuth(authn.Anonymous)}
	})

	AfterEach(func() {
		server.Close()
	})

	It("carries the artifacts of a single-platform image into the final repo and the cache repo", func(ctx SpecContext) {
		digest := pushImage(ctx, stagesRepo, "v1")
		attach(ctx, stagesRepo, digest, `{"scope":"app"}`)
		copyManifestByDigest(ctx, stagesRepo, finalRepo, digest)
		copyManifestByDigest(ctx, stagesRepo, cacheRepo, digest)

		finalDesc := &imagePkg.StageDesc{
			StageID: imagePkg.NewStageID("digest", 1),
			Info:    &imagePkg.Info{Repository: finalRepo, RepoDigest: finalRepo + "@" + digest},
		}

		tree := image.NewImagesTree(nil, image.ImagesTreeOptions{})
		tree.AppendImageForTests(newImage(ctx, "linux/amd64", stagesRepo, digest, finalDesc))

		Expect(newPhase(tree, cacheStorage(cacheRepo)).propagateArtifacts(ctx)).To(Succeed())

		expectAttached(ctx, finalRepo, digest, `{"scope":"app"}`)
		expectAttached(ctx, cacheRepo, digest, `{"scope":"app"}`)
	})

	It("leaves the artifacts alone when the image was not published to a final repo", func(ctx SpecContext) {
		digest := pushImage(ctx, stagesRepo, "v1")
		attach(ctx, stagesRepo, digest, `{"scope":"app"}`)
		copyManifestByDigest(ctx, stagesRepo, finalRepo, digest)

		tree := image.NewImagesTree(nil, image.ImagesTreeOptions{})
		tree.AppendImageForTests(newImage(ctx, "linux/amd64", stagesRepo, digest, nil))

		Expect(newPhase(tree).propagateArtifacts(ctx)).To(Succeed())

		expectNothingAttached(ctx, finalRepo, digest)
	})

	It("carries per-platform artifacts onto the platform manifests and image-level artifacts onto the index", func(ctx SpecContext) {
		platforms := []string{"linux/amd64", "linux/arm64"}
		indexDigest, children := pushIndex(ctx, stagesRepo, "index", platforms)

		attach(ctx, stagesRepo, indexDigest, `{"scope":"image"}`)
		attach(ctx, stagesRepo, children[0], `{"scope":"amd64"}`)
		attach(ctx, stagesRepo, children[1], `{"scope":"arm64"}`)

		copyManifestByDigest(ctx, stagesRepo, finalRepo, indexDigest)

		tree := image.NewImagesTree(nil, image.ImagesTreeOptions{})
		images := make([]*image.Image, 0, len(platforms))
		for i, platform := range platforms {
			img := newImage(ctx, platform, stagesRepo, children[i], nil)
			images = append(images, img)
			tree.AppendImageForTests(img)
		}

		multiImg := image.NewMultiplatformImage("app", images, 0, 1)
		multiImg.SetStageDesc(&imagePkg.StageDesc{
			StageID: imagePkg.NewStageID("digest", 1),
			Info:    &imagePkg.Info{Repository: stagesRepo, RepoDigest: stagesRepo + "@" + indexDigest},
		})
		multiImg.SetFinalStageDesc(&imagePkg.StageDesc{
			StageID: imagePkg.NewStageID("digest", 1),
			Info:    &imagePkg.Info{Repository: finalRepo, RepoDigest: finalRepo + "@" + indexDigest},
		})
		tree.SetMultiplatformImage(multiImg)

		// A cache repo never holds the index digest, so offering it the image-level
		// artifact could only ever warn; the platform manifests do travel there.
		Expect(newPhase(tree, cacheStorage(cacheRepo)).propagateArtifacts(ctx)).To(Succeed())

		expectAttached(ctx, finalRepo, indexDigest, `{"scope":"image"}`)
		expectAttached(ctx, finalRepo, children[0], `{"scope":"amd64"}`)
		expectAttached(ctx, finalRepo, children[1], `{"scope":"arm64"}`)
		expectNothingAttached(ctx, cacheRepo, indexDigest)
	})
})
