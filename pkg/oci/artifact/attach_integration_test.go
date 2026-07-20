package artifact_test

import (
	"context"
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

	"github.com/werf/werf/v2/pkg/oci/artifact"
)

var _ = Describe("Attach / PullFallbackIndex (integration)", func() {
	const artifactType = "application/vnd.dsse.envelope.v1+json"

	var (
		server       *httptest.Server
		repo         string
		parentDigest string
		remoteOpts   []remote.Option
	)

	BeforeEach(func(ctx SpecContext) {
		server = httptest.NewServer(registry.New())
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

	attach := func(ctx context.Context, payload []byte, imageName string) {
		store := artifact.NewOCIStore(repo, imageName, remoteOpts...)
		Expect(store.Attach(ctx, parentDigest, artifactType, payload, "", "")).To(Succeed())
	}

	pullIndex := func(ctx context.Context) *v1.IndexManifest {
		opts := append([]remote.Option{remote.WithContext(ctx)}, remoteOpts...)
		idx, err := artifact.PullFallbackIndex(ctx, repo, parentDigest, opts...)
		Expect(err).To(Succeed())
		im, err := idx.IndexManifest()
		Expect(err).To(Succeed())
		return im
	}

	// werfEntries returns only werf-managed descriptors, ignoring entries that
	// go-containerregistry writes into the same fallback tag when the registry
	// lacks Referrers API support (they carry the empty-config artifactType).
	werfEntries := func(im *v1.IndexManifest) []v1.Descriptor {
		var out []v1.Descriptor
		for _, m := range im.Manifests {
			if m.ArtifactType == artifactType {
				out = append(out, m)
			}
		}
		return out
	}

	It("should attach an artifact without imageName", func(ctx SpecContext) {
		attach(ctx, []byte(`{"a":1}`), "")

		im := pullIndex(ctx)
		Expect(werfEntries(im)).To(HaveLen(1))
	})

	It("should deduplicate artifacts of the same type when imageName is empty", func(ctx SpecContext) {
		attach(ctx, []byte(`{"v":1}`), "")
		attach(ctx, []byte(`{"v":2}`), "")

		im := pullIndex(ctx)
		Expect(werfEntries(im)).To(HaveLen(1))

		store := artifact.NewOCIStore(repo, "", remoteOpts...)
		content, err := store.GetAttachedContentAny(ctx, parentDigest, artifactType)
		Expect(err).To(Succeed())
		Expect(content).To(MatchJSON(`{"v":2}`))
	})

	It("should keep separate entries for different imageNames", func(ctx SpecContext) {
		attach(ctx, []byte(`{"img":"a"}`), "app-a")
		attach(ctx, []byte(`{"img":"b"}`), "app-b")

		im := pullIndex(ctx)
		Expect(werfEntries(im)).To(HaveLen(2))
	})

	It("should round-trip artifact content via GetAttachedContent", func(ctx SpecContext) {
		attach(ctx, []byte(`{"vex":"data"}`), "my-app")

		store := artifact.NewOCIStore(repo, "my-app", remoteOpts...)
		content, err := store.GetAttachedContent(ctx, parentDigest, artifactType)
		Expect(err).To(Succeed())
		Expect(content).To(MatchJSON(`{"vex":"data"}`))
	})

	It("should return empty index for a digest with no attachments", func(ctx SpecContext) {
		otherParent, err := random.Image(128, 1)
		Expect(err).To(Succeed())
		otherRef, err := name.NewTag(repo + ":other")
		Expect(err).To(Succeed())
		Expect(remote.Write(otherRef, otherParent, append([]remote.Option{remote.WithContext(ctx)}, remoteOpts...)...)).To(Succeed())
		otherDigest, err := otherParent.Digest()
		Expect(err).To(Succeed())

		opts := append([]remote.Option{remote.WithContext(ctx)}, remoteOpts...)
		idx, err := artifact.PullFallbackIndex(ctx, repo, otherDigest.String(), opts...)
		Expect(err).To(Succeed())
		im, err := idx.IndexManifest()
		Expect(err).To(Succeed())
		Expect(im.Manifests).To(BeEmpty())
	})
})
