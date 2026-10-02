package storage

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

	"github.com/werf/werf/v3/pkg/attestation"
	"github.com/werf/werf/v3/pkg/docker_registry"
	"github.com/werf/werf/v3/pkg/image"
	"github.com/werf/werf/v3/pkg/oci/artifact"
)

type copyFromStorageRegistryStub struct {
	docker_registry.Interface

	repoDigestByReference map[string]string
	copied                []string
}

func (r *copyFromStorageRegistryStub) GetRepoImage(_ context.Context, reference string) (*image.Info, error) {
	repoDigest, found := r.repoDigestByReference[reference]
	if !found {
		return nil, &manifestUnknownError{}
	}
	return &image.Info{Name: reference, RepoDigest: repoDigest}, nil
}

func (r *copyFromStorageRegistryStub) IsTagExist(_ context.Context, _ string, _ ...docker_registry.Option) (bool, error) {
	return false, nil
}

func (r *copyFromStorageRegistryStub) CopyImage(_ context.Context, sourceReference, destinationReference string, _ docker_registry.CopyImageOptions) error {
	r.copied = append(r.copied, sourceReference+" -> "+destinationReference)
	return nil
}

type manifestUnknownError struct{}

func (e *manifestUnknownError) Error() string { return "MANIFEST_UNKNOWN: manifest unknown" }

var _ = Describe("RepoStagesStorage.CopyFromStorage", func() {
	const projectName = "project"

	var (
		server     *httptest.Server
		srcRepo    string
		dstRepo    string
		remoteOpts []remote.Option
		stageID    image.StageID
	)

	BeforeEach(func(ctx SpecContext) {
		Expect(docker_registry.Init(ctx, false, false, nil, nil)).To(Succeed())

		server = httptest.NewServer(registry.New())
		host := strings.TrimPrefix(server.URL, "http://")
		srcRepo = host + "/test/src"
		dstRepo = host + "/test/dst"
		remoteOpts = []remote.Option{remote.WithAuth(authn.Anonymous)}
		stageID = *image.NewStageID("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", 1)
	})

	AfterEach(func() {
		server.Close()
	})

	pushStage := func(ctx SpecContext, repos ...string) string {
		img, err := random.Image(256, 1)
		Expect(err).To(Succeed())
		dgst, err := img.Digest()
		Expect(err).To(Succeed())

		for _, repo := range repos {
			ref, err := name.NewDigest(repo + "@" + dgst.String())
			Expect(err).To(Succeed())
			Expect(remote.Write(ref, img, append([]remote.Option{remote.WithContext(ctx)}, remoteOpts...)...)).To(Succeed())
		}

		return dgst.String()
	}

	newStorage := func(repo string, stub *copyFromStorageRegistryStub) *RepoStagesStorage {
		return NewRepoStagesStorage(&NewRepoStagesStorageOptions{
			RepoAddress:    repo,
			DockerRegistry: stub,
			SkipMetaCheck:  true,
		})
	}

	It("attaches the artifacts of the source to a destination that already holds the stage without them", func(ctx SpecContext) {
		digest := pushStage(ctx, srcRepo, dstRepo)
		srcStore := artifact.NewOCIStore(srcRepo, "app", remoteOpts...)
		Expect(srcStore.Attach(ctx, digest, attestation.DSSEMediaType, []byte(`{"v":1}`), "checksum-v1", "", "")).To(Succeed())

		src := newStorage(srcRepo, &copyFromStorageRegistryStub{})
		stub := &copyFromStorageRegistryStub{repoDigestByReference: map[string]string{
			dstRepo + ":" + stageID.String(): dstRepo + "@" + digest,
		}}
		dst := newStorage(dstRepo, stub)

		desc, err := dst.CopyFromStorage(ctx, src, projectName, stageID, CopyFromStorageOptions{})
		Expect(err).NotTo(HaveOccurred())
		Expect(desc.Info.GetDigest()).To(Equal(digest))
		Expect(stub.copied).To(BeEmpty(), "the manifest was in place, nothing to copy")

		dstStore := artifact.NewOCIStore(dstRepo, "app", remoteOpts...)
		content, err := dstStore.GetAttachedContent(ctx, digest, attestation.DSSEMediaType, nil)
		Expect(err).To(Succeed())
		Expect(content).To(MatchJSON(`{"v":1}`))
	})

	It("does not fail on a destination that already holds a stage the source does not", func(ctx SpecContext) {
		digest := pushStage(ctx, dstRepo)

		src := newStorage(srcRepo, &copyFromStorageRegistryStub{})
		dst := newStorage(dstRepo, &copyFromStorageRegistryStub{repoDigestByReference: map[string]string{
			dstRepo + ":" + stageID.String(): dstRepo + "@" + digest,
		}})

		desc, err := dst.CopyFromStorage(ctx, src, projectName, stageID, CopyFromStorageOptions{})
		Expect(err).NotTo(HaveOccurred())
		Expect(desc.Info.GetDigest()).To(Equal(digest))
	})
})
