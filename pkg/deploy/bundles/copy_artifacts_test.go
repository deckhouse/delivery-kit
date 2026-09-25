package bundles

import (
	"fmt"
	"net/http/httptest"
	"strings"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/registry"
	"github.com/google/go-containerregistry/pkg/v1/random"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	chartcommon "github.com/werf/nelm/v2/pkg/helm/pkg/chart/common"
	chart "github.com/werf/nelm/v2/pkg/helm/pkg/chart/v2"
	"github.com/werf/werf/v3/pkg/attestation"
	"github.com/werf/werf/v3/pkg/docker_registry"
	"github.com/werf/werf/v3/pkg/image"
	"github.com/werf/werf/v3/pkg/logging"
	"github.com/werf/werf/v3/pkg/oci/artifact"
	bundles_registry "github.com/werf/werf/v3/pkg/ref"
)

var _ = Describe("Bundle copy artifacts", func() {
	const imageTag = "tag-1"

	var (
		server     *httptest.Server
		srcRepo    string
		dstRepo    string
		remoteOpts []remote.Option
	)

	pushImage := func(ctx SpecContext, repo string) string {
		img, err := random.Image(256, 1)
		Expect(err).To(Succeed())

		ref, err := name.NewTag(repo + ":" + imageTag)
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

	// copyBundle runs a remote-to-remote bundle copy of a single-image bundle. The
	// bundle copy itself goes through the stub, which holds archives rather than
	// manifests, so the destination manifest has to be placed separately — at the
	// same digest, the way a registry copy places it.
	copyBundle := func(ctx SpecContext, digest string) {
		srcRef := fmt.Sprintf("%s:%s", srcRepo, imageTag)
		ch := &chart.Chart{
			Metadata: &chart.Metadata{
				APIVersion: "v2",
				Name:       "testproject",
				Version:    "1.2.3",
				Type:       "application",
			},
			Values: map[string]interface{}{
				"werf": map[string]interface{}{
					"image": map[string]interface{}{"image-1": srcRef},
					"repo":  srcRepo,
				},
			},
			Raw: []*chartcommon.File{
				{
					Name: "values.yaml",
					Data: []byte(fmt.Sprintf("werf:\n  image:\n    image-1: %s\n  repo: %s\n", srcRef, srcRepo)),
				},
			},
		}

		bundlesRegistryClient := NewBundlesRegistryClientStub()
		registryClient := NewDockerRegistryStub()
		registryClient.ImagesByReference[srcRef] = []byte(`image-1-bytes`)
		registryClient.RepoImagesByReference[srcRef] = &image.Info{RepoDigest: srcRepo + "@" + digest}

		fromAddr, err := bundles_registry.ParseAddr(srcRepo + ":1.2.3")
		Expect(err).NotTo(HaveOccurred())
		from := NewRemoteBundle(fromAddr.RegistryAddress, bundlesRegistryClient, registryClient)
		bundlesRegistryClient.StubCharts[fromAddr.RegistryAddress.FullName()] = ch

		toAddr, err := bundles_registry.ParseAddr(dstRepo + ":4.5.6")
		Expect(err).NotTo(HaveOccurred())
		to := NewRemoteBundle(toAddr.RegistryAddress, bundlesRegistryClient, registryClient)

		Expect(from.CopyTo(logging.WithLogger(ctx), to, copyToOptions{})).To(Succeed())
	}

	BeforeEach(func(ctx SpecContext) {
		Expect(docker_registry.Init(ctx, false, false, nil, nil)).To(Succeed())

		server = httptest.NewServer(registry.New())
		host := strings.TrimPrefix(server.URL, "http://")
		srcRepo = host + "/group/testproject"
		dstRepo = host + "/group2/testproject2"
		remoteOpts = []remote.Option{remote.WithAuth(authn.Anonymous)}
	})

	AfterEach(func() {
		server.Close()
	})

	It("should carry the artifacts of the images it copies between registries", func(ctx SpecContext) {
		digest := pushImage(ctx, srcRepo)

		srcStore := artifact.NewOCIStore(srcRepo, "image-1", remoteOpts...)
		Expect(srcStore.Attach(ctx, digest, attestation.DSSEMediaType, []byte(`{"sbom":true}`), "checksum-v1", "", "")).To(Succeed())

		copyImageByDigest(ctx, srcRepo, dstRepo, digest)
		copyBundle(ctx, digest)

		dstStore := artifact.NewOCIStore(dstRepo, "image-1", remoteOpts...)
		content, err := dstStore.GetAttachedContent(ctx, digest, attestation.DSSEMediaType, nil)
		Expect(err).To(Succeed())
		Expect(content).To(MatchJSON(`{"sbom":true}`))
	})

	It("should copy a bundle whose images carry no artifacts", func(ctx SpecContext) {
		digest := pushImage(ctx, srcRepo)

		copyImageByDigest(ctx, srcRepo, dstRepo, digest)
		copyBundle(ctx, digest)

		idx, err := artifact.PullFallbackIndex(ctx, dstRepo, digest, remoteOpts...)
		Expect(err).To(Succeed())
		im, err := idx.IndexManifest()
		Expect(err).To(Succeed())
		Expect(im.Manifests).To(BeEmpty())
	})
})
