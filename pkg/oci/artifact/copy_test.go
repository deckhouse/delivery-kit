package artifact_test

import (
	"fmt"
	"io"
	"net/http"
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

	"github.com/werf/werf/v3/pkg/image"
	"github.com/werf/werf/v3/pkg/oci/artifact"
)

var _ = Describe("CopyAttachedArtifacts (integration)", func() {
	const artifactType = "application/vnd.dsse.envelope.v1+json"

	var (
		server     *httptest.Server
		srcRepo    string
		dstRepo    string
		srcDigest  string
		remoteOpts []remote.Option
	)

	pushRandomImage := func(ctx SpecContext, repo, tag string) string {
		img, err := random.Image(256, 1)
		Expect(err).To(Succeed())

		ref, err := name.NewTag(repo + ":" + tag)
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

	pullIndex := func(ctx SpecContext, repo, parentDigest string) *v1.IndexManifest {
		opts := append([]remote.Option{remote.WithContext(ctx)}, remoteOpts...)
		idx, err := artifact.PullFallbackIndex(ctx, repo, parentDigest, opts...)
		Expect(err).To(Succeed())
		im, err := idx.IndexManifest()
		Expect(err).To(Succeed())
		return im
	}

	BeforeEach(func(ctx SpecContext) {
		server = httptest.NewServer(registry.New())
		host := strings.TrimPrefix(server.URL, "http://")
		srcRepo = host + "/test/src"
		dstRepo = host + "/test/dst"
		remoteOpts = []remote.Option{remote.WithAuth(authn.Anonymous)}

		srcDigest = pushRandomImage(ctx, srcRepo, "v1")
	})

	AfterEach(func() {
		server.Close()
	})

	It("should copy attached artifacts onto the same digest in another repo", func(ctx SpecContext) {
		srcStore := artifact.NewOCIStore(srcRepo, "my-app", remoteOpts...)
		Expect(srcStore.Attach(ctx, srcDigest, artifactType, []byte(`{"v":1}`), "checksum-v1", "linux/amd64", "")).To(Succeed())

		copyImageByDigest(ctx, srcRepo, dstRepo, srcDigest)

		Expect(artifact.CopyAttachedArtifacts(ctx, srcRepo, srcDigest, dstRepo, srcDigest, remoteOpts...)).To(Succeed())

		dstStore := artifact.NewOCIStore(dstRepo, "my-app", remoteOpts...)
		content, err := dstStore.GetAttachedContent(ctx, srcDigest, artifactType, nil)
		Expect(err).To(Succeed())
		Expect(content).To(MatchJSON(`{"v":1}`))

		im := pullIndex(ctx, dstRepo, srcDigest)
		Expect(im.Manifests).To(HaveLen(1))
		Expect(im.Manifests[0].Annotations).To(HaveKeyWithValue(image.WerfChecksumAnnotation, "checksum-v1"))
		Expect(im.Manifests[0].Annotations).To(HaveKeyWithValue(image.WerfPlatformAnnotation, "linux/amd64"))
	})

	It("should copy attached artifacts onto a different parent digest", func(ctx SpecContext) {
		srcStore := artifact.NewOCIStore(srcRepo, "my-app", remoteOpts...)
		Expect(srcStore.Attach(ctx, srcDigest, artifactType, []byte(`{"v":1}`), "checksum-v1", "", "")).To(Succeed())

		dstDigest := pushRandomImage(ctx, dstRepo, "v1")
		Expect(dstDigest).ToNot(Equal(srcDigest))

		Expect(artifact.CopyAttachedArtifacts(ctx, srcRepo, srcDigest, dstRepo, dstDigest, remoteOpts...)).To(Succeed())

		dstStore := artifact.NewOCIStore(dstRepo, "my-app", remoteOpts...)
		content, err := dstStore.GetAttachedContent(ctx, dstDigest, artifactType, nil)
		Expect(err).To(Succeed())
		Expect(content).To(MatchJSON(`{"v":1}`))
	})

	It("should be idempotent", func(ctx SpecContext) {
		srcStore := artifact.NewOCIStore(srcRepo, "my-app", remoteOpts...)
		Expect(srcStore.Attach(ctx, srcDigest, artifactType, []byte(`{"v":1}`), "checksum-v1", "", "")).To(Succeed())

		copyImageByDigest(ctx, srcRepo, dstRepo, srcDigest)

		Expect(artifact.CopyAttachedArtifacts(ctx, srcRepo, srcDigest, dstRepo, srcDigest, remoteOpts...)).To(Succeed())
		Expect(artifact.CopyAttachedArtifacts(ctx, srcRepo, srcDigest, dstRepo, srcDigest, remoteOpts...)).To(Succeed())

		im := pullIndex(ctx, dstRepo, srcDigest)
		Expect(im.Manifests).To(HaveLen(1))
	})

	It("should copy artifacts of multiple images attached to the same parent", func(ctx SpecContext) {
		storeA := artifact.NewOCIStore(srcRepo, "app-a", remoteOpts...)
		Expect(storeA.Attach(ctx, srcDigest, artifactType, []byte(`{"app":"a"}`), "checksum-a", "", "")).To(Succeed())
		storeB := artifact.NewOCIStore(srcRepo, "app-b", remoteOpts...)
		Expect(storeB.Attach(ctx, srcDigest, artifactType, []byte(`{"app":"b"}`), "checksum-b", "", "")).To(Succeed())

		copyImageByDigest(ctx, srcRepo, dstRepo, srcDigest)

		Expect(artifact.CopyAttachedArtifacts(ctx, srcRepo, srcDigest, dstRepo, srcDigest, remoteOpts...)).To(Succeed())

		dstStoreA := artifact.NewOCIStore(dstRepo, "app-a", remoteOpts...)
		contentA, err := dstStoreA.GetAttachedContent(ctx, srcDigest, artifactType, nil)
		Expect(err).To(Succeed())
		Expect(contentA).To(MatchJSON(`{"app":"a"}`))

		dstStoreB := artifact.NewOCIStore(dstRepo, "app-b", remoteOpts...)
		contentB, err := dstStoreB.GetAttachedContent(ctx, srcDigest, artifactType, nil)
		Expect(err).To(Succeed())
		Expect(contentB).To(MatchJSON(`{"app":"b"}`))
	})

	It("should be a no-op when the source has no attached artifacts", func(ctx SpecContext) {
		Expect(artifact.CopyAttachedArtifacts(ctx, srcRepo, srcDigest, dstRepo, srcDigest, remoteOpts...)).To(Succeed())

		im := pullIndex(ctx, dstRepo, srcDigest)
		Expect(im.Manifests).To(BeEmpty())
	})

	Describe("CopyAllAttachedArtifacts", func() {
		// The index carries a platform per manifest the way a werf multi-platform
		// image does: entries without one are not platform manifests and are not
		// traversed.
		pushMultiplatformIndex := func(ctx SpecContext, repo, tag string) (string, []string) {
			idx := v1.ImageIndex(empty.Index)
			var children []string

			for _, platform := range []string{"linux/amd64", "linux/arm64"} {
				img, err := random.Image(256, 1)
				Expect(err).To(Succeed())

				parsed, err := v1.ParsePlatform(platform)
				Expect(err).To(Succeed())

				idx = mutate.AppendManifests(idx, mutate.IndexAddendum{
					Add:        img,
					Descriptor: v1.Descriptor{Platform: parsed},
				})

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

		copyIndexByDigest := func(ctx SpecContext, fromRepo, toRepo, digest string) {
			fromRef, err := name.NewDigest(fromRepo + "@" + digest)
			Expect(err).To(Succeed())
			idx, err := remote.Index(fromRef, append([]remote.Option{remote.WithContext(ctx)}, remoteOpts...)...)
			Expect(err).To(Succeed())

			toRef, err := name.NewDigest(toRepo + "@" + digest)
			Expect(err).To(Succeed())
			Expect(remote.WriteIndex(toRef, idx, append([]remote.Option{remote.WithContext(ctx)}, remoteOpts...)...)).To(Succeed())
		}

		It("should carry the artifacts of every manifest an index references", func(ctx SpecContext) {
			indexDigest, children := pushMultiplatformIndex(ctx, srcRepo, "index")

			store := artifact.NewOCIStore(srcRepo, "my-app", remoteOpts...)
			Expect(store.Attach(ctx, indexDigest, artifactType, []byte(`{"scope":"image"}`), "checksum-index", "", "")).To(Succeed())
			for i, child := range children {
				payload := fmt.Sprintf(`{"scope":"platform-%d"}`, i)
				Expect(store.Attach(ctx, child, artifactType, []byte(payload), fmt.Sprintf("checksum-%d", i), "", "")).To(Succeed())
			}

			copyIndexByDigest(ctx, srcRepo, dstRepo, indexDigest)

			Expect(artifact.CopyAllAttachedArtifacts(ctx, srcRepo, indexDigest, dstRepo, indexDigest, remoteOpts...)).To(Succeed())

			dstStore := artifact.NewOCIStore(dstRepo, "my-app", remoteOpts...)
			content, err := dstStore.GetAttachedContent(ctx, indexDigest, artifactType, nil)
			Expect(err).To(Succeed())
			Expect(content).To(MatchJSON(`{"scope":"image"}`))

			for i, child := range children {
				childContent, err := dstStore.GetAttachedContent(ctx, child, artifactType, nil)
				Expect(err).To(Succeed())
				Expect(childContent).To(MatchJSON(fmt.Sprintf(`{"scope":"platform-%d"}`, i)))
			}
		})

		It("should not move an artifact of a referenced manifest onto the index digest", func(ctx SpecContext) {
			indexDigest, children := pushMultiplatformIndex(ctx, srcRepo, "index")

			store := artifact.NewOCIStore(srcRepo, "my-app", remoteOpts...)
			Expect(store.Attach(ctx, children[0], artifactType, []byte(`{"scope":"platform-0"}`), "checksum-0", "", "")).To(Succeed())

			copyIndexByDigest(ctx, srcRepo, dstRepo, indexDigest)

			Expect(artifact.CopyAllAttachedArtifacts(ctx, srcRepo, indexDigest, dstRepo, indexDigest, remoteOpts...)).To(Succeed())

			Expect(pullIndex(ctx, dstRepo, indexDigest).Manifests).To(BeEmpty())
			Expect(pullIndex(ctx, dstRepo, children[0]).Manifests).To(HaveLen(1))
		})

		It("should be a no-op when the source does not hold the manifest", func(ctx SpecContext) {
			absentDigest := pushRandomImage(ctx, dstRepo, "only-in-dst")

			Expect(artifact.CopyAllAttachedArtifacts(ctx, srcRepo, absentDigest, dstRepo, absentDigest, remoteOpts...)).To(Succeed())

			Expect(pullIndex(ctx, dstRepo, absentDigest).Manifests).To(BeEmpty())
		})

		It("should fail when the source manifest cannot be read for a reason other than absence", func(ctx SpecContext) {
			indexDigest, _ := pushMultiplatformIndex(ctx, srcRepo, "index")
			copyIndexByDigest(ctx, srcRepo, dstRepo, indexDigest)

			upstream := server.Listener.Addr().String()
			failing := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/manifests/"+indexDigest) {
					http.Error(w, "registry unavailable", http.StatusInternalServerError)
					return
				}
				r.URL.Scheme = "http"
				r.URL.Host = upstream
				r.RequestURI = ""
				resp, err := http.DefaultTransport.RoundTrip(r)
				if err != nil {
					http.Error(w, err.Error(), http.StatusBadGateway)
					return
				}
				defer resp.Body.Close()
				for k, vs := range resp.Header {
					w.Header()[k] = vs
				}
				w.WriteHeader(resp.StatusCode)
				_, _ = io.Copy(w, resp.Body)
			}))
			defer failing.Close()

			failingSrcRepo := strings.TrimPrefix(failing.URL, "http://") + "/test/src"

			err := artifact.CopyAllAttachedArtifacts(ctx, failingSrcRepo, indexDigest, dstRepo, indexDigest, remoteOpts...)
			Expect(err).To(MatchError(ContainSubstring("list index manifests")))
		})
	})
})
