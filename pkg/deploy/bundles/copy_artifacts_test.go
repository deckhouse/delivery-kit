package bundles

import (
	"context"
	"path/filepath"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	nelmcommon "github.com/werf/nelm/v2/pkg/common"
	"github.com/werf/werf/v3/pkg/attestation"
	"github.com/werf/werf/v3/pkg/docker_registry"
	"github.com/werf/werf/v3/pkg/logging"
	"github.com/werf/werf/v3/pkg/oci/artifact"
)

var _ = Describe("Bundle copy artifacts", func() {
	var (
		ctx              context.Context
		fromRepo, toRepo string
		imageDigest      string
		copyOpts         CopyOptions
		remoteOpts       []remote.Option
	)

	BeforeEach(func() {
		ctx = logging.WithLogger(context.Background())
		Expect(docker_registry.Init(ctx, false, false, nil, nil)).To(Succeed())

		registryHost := startTestRegistry()
		fromRepo = registryHost + "/group/testproject"
		toRepo = registryHost + "/group2/testproject2"
		imageDigest = pushTestImage(fromRepo + ":tag-1")
		remoteOpts = []remote.Option{remote.WithAuth(authn.Anonymous)}
		copyOpts = CopyOptions{
			ChartRepoConnectionOptions: nelmcommon.ChartRepoConnectionOptions{ChartRepoInsecure: true},
			RegistryCredentialsPath:    testCredentialsPath(),
		}

		pushOldBundle(newTestRegistryClient(ctx), fromRepo, "1.2.3", oldBundleValues(fromRepo, imageDigest))
	})

	It("should carry the artifacts of the images it copies between registries", func() {
		srcStore := artifact.NewOCIStore(fromRepo, "app", remoteOpts...)
		Expect(srcStore.Attach(ctx, imageDigest, attestation.DSSEMediaType, []byte(`{"sbom":true}`), "checksum-v1", "", "")).To(Succeed())

		Expect(Copy(ctx, fromRepo+":1.2.3", toRepo+":4.5.6", copyOpts)).To(Succeed())

		dstStore := artifact.NewOCIStore(toRepo, "app", remoteOpts...)
		content, err := dstStore.GetAttachedContent(ctx, imageDigest, attestation.DSSEMediaType, nil, artifact.GetAttachedOptions{})
		Expect(err).To(Succeed())
		Expect(content).To(MatchJSON(`{"sbom":true}`))
	})

	It("should copy a bundle whose images carry no artifacts", func() {
		Expect(Copy(ctx, fromRepo+":1.2.3", toRepo+":4.5.6", copyOpts)).To(Succeed())

		idx, err := artifact.PullFallbackIndex(ctx, toRepo, imageDigest, remoteOpts...)
		Expect(err).To(Succeed())
		im, err := idx.IndexManifest()
		Expect(err).To(Succeed())
		Expect(im.Manifests).To(BeEmpty())
	})

	It("should not look for artifacts when copying from an archive", func() {
		archivePath := filepath.Join(GinkgoT().TempDir(), "bundle.tar.gz")
		Expect(Copy(ctx, fromRepo+":1.2.3", "archive:"+archivePath, copyOpts)).To(Succeed())
		Expect(Copy(ctx, "archive:"+archivePath, toRepo+":4.5.6", copyOpts)).To(Succeed())

		Expect(testImageDigest(toRepo + ":tag-1")).To(Equal(imageDigest))
	})
})
