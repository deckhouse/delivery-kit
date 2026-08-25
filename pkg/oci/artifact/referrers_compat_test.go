package artifact_test

import (
	"net/http/httptest"
	"strings"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/registry"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/random"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/werf/werf/v2/pkg/image"
	"github.com/werf/werf/v2/pkg/oci/artifact"
)

// These specs lock the properties that let werf move reads to the Referrers API
// without changing the stored artifact format. werf itself never queries that API:
// it stores artifacts so that a registry supporting the API reports them correctly.
//
// The distribution spec requires a referrers descriptor to carry the artifactType of
// the manifest, falling back to the config media type when the manifest declares no
// artifactType, and to carry the annotations of the manifest. The registry used here
// implements the former but not the latter, so annotations are asserted on the stored
// manifest instead.
var _ = Describe("Referrers API forward compatibility", func() {
	const artifactType = "application/vnd.dsse.envelope.v1+json"

	var (
		server       *httptest.Server
		repo         string
		parentDigest string
		remoteOpts   []remote.Option
	)

	BeforeEach(func(ctx SpecContext) {
		server = httptest.NewServer(registry.New(registry.WithReferrersSupport(true)))
		host := strings.TrimPrefix(server.URL, "http://")
		repo = host + "/test/app"
		remoteOpts = []remote.Option{remote.WithAuth(authn.Anonymous)}

		parent, err := random.Image(256, 1)
		Expect(err).To(Succeed())

		parentRef, err := name.NewTag(repo + ":v1")
		Expect(err).To(Succeed())
		Expect(remote.Write(parentRef, parent, append([]remote.Option{remote.WithContext(ctx)}, remoteOpts...)...)).To(Succeed())

		dgst, err := parent.Digest()
		Expect(err).To(Succeed())
		parentDigest = dgst.String()
	})

	AfterEach(func() {
		server.Close()
	})

	attach := func(ctx SpecContext, imageName string) {
		store := artifact.NewOCIStore(repo, imageName, remoteOpts...)
		Expect(store.Attach(ctx, parentDigest, artifactType, []byte(`{"a":1}`), "checksum-v1", "linux/amd64", "")).To(Succeed())
	}

	referrers := func(ctx SpecContext) *v1.IndexManifest {
		parentRef, err := name.NewDigest(repo + "@" + parentDigest)
		Expect(err).To(Succeed())
		idx, err := remote.Referrers(parentRef, append([]remote.Option{remote.WithContext(ctx)}, remoteOpts...)...)
		Expect(err).To(Succeed())
		im, err := idx.IndexManifest()
		Expect(err).To(Succeed())
		return im
	}

	It("should expose the attached artifact through the Referrers API", func(ctx SpecContext) {
		attach(ctx, "my-app")

		im := referrers(ctx)
		Expect(im.Manifests).To(HaveLen(1))
	})

	It("should report the artifact type through the Referrers API", func(ctx SpecContext) {
		attach(ctx, "my-app")

		im := referrers(ctx)
		Expect(im.Manifests[0].ArtifactType).To(Equal(artifactType))
	})

	It("should still maintain the fallback index on a referrers-capable registry", func(ctx SpecContext) {
		attach(ctx, "my-app")

		idx, err := artifact.PullFallbackIndex(ctx, repo, parentDigest, append([]remote.Option{remote.WithContext(ctx)}, remoteOpts...)...)
		Expect(err).To(Succeed())
		im, err := idx.IndexManifest()
		Expect(err).To(Succeed())

		Expect(im.Manifests).To(HaveLen(1))
		Expect(im.Manifests[0].ArtifactType).To(Equal(artifactType))
		Expect(im.Manifests[0].Annotations).To(HaveKeyWithValue(image.WerfImageNameAnnotation, "my-app"))
	})

	It("should keep the annotations a referrers descriptor is built from on the stored manifest", func(ctx SpecContext) {
		attach(ctx, "my-app")

		im := referrers(ctx)
		artifactRef, err := name.NewDigest(repo + "@" + im.Manifests[0].Digest.String())
		Expect(err).To(Succeed())

		img, err := remote.Image(artifactRef, append([]remote.Option{remote.WithContext(ctx)}, remoteOpts...)...)
		Expect(err).To(Succeed())
		manifest, err := img.Manifest()
		Expect(err).To(Succeed())

		Expect(manifest.Annotations).To(HaveKeyWithValue(image.WerfImageNameAnnotation, "my-app"))
		Expect(manifest.Annotations).To(HaveKeyWithValue(image.WerfChecksumAnnotation, "checksum-v1"))
		Expect(manifest.Annotations).To(HaveKeyWithValue(image.WerfPlatformAnnotation, "linux/amd64"))
	})
})
