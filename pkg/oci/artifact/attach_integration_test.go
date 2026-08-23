package artifact_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/registry"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/random"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	gcrtypes "github.com/google/go-containerregistry/pkg/v1/types"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/samber/lo/parallel"

	"github.com/werf/werf/v2/pkg/attestation"
	"github.com/werf/werf/v2/pkg/docker_registry"
	"github.com/werf/werf/v2/pkg/image"
	"github.com/werf/werf/v2/pkg/oci/artifact"
)

var _ = Describe("Attach / PullFallbackIndex (integration)", func() {
	artifactType := attestation.DSSEMediaType

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
		Expect(store.Attach(ctx, parentDigest, artifactType, payload, "", "", "")).To(Succeed())
	}

	pullIndex := func(ctx context.Context) *v1.IndexManifest {
		opts := append([]remote.Option{remote.WithContext(ctx)}, remoteOpts...)
		idx, err := artifact.PullFallbackIndex(ctx, repo, parentDigest, opts...)
		Expect(err).To(Succeed())
		im, err := idx.IndexManifest()
		Expect(err).To(Succeed())
		return im
	}

	attachE := func(ctx context.Context, payload []byte, imageName string) error {
		store := artifact.NewOCIStore(repo, imageName, remoteOpts...)
		return store.Attach(ctx, parentDigest, artifactType, payload, "", "", "")
	}

	It("should attach an artifact without imageName", func(ctx SpecContext) {
		attach(ctx, []byte(`{"a":1}`), "")

		im := pullIndex(ctx)
		Expect(im.Manifests).To(HaveLen(1))
	})

	It("should not leave a duplicate entry written by go-containerregistry", func(ctx SpecContext) {
		attach(ctx, []byte(`{"a":1}`), "my-app")

		im := pullIndex(ctx)
		Expect(im.Manifests).To(HaveLen(1))
		Expect(im.Manifests[0].ArtifactType).To(Equal(artifactType))
		Expect(im.Manifests[0].Annotations[image.WerfImageNameAnnotation]).To(Equal("my-app"))
	})

	It("should write werf annotations into the artifact manifest itself", func(ctx SpecContext) {
		store := artifact.NewOCIStore(repo, "my-app", remoteOpts...)
		Expect(store.Attach(ctx, parentDigest, artifactType, []byte(`{"a":1}`), "checksum-v1", "linux/amd64", "")).To(Succeed())

		im := pullIndex(ctx)
		Expect(im.Manifests).To(HaveLen(1))

		artifactRef, err := name.NewDigest(repo + "@" + im.Manifests[0].Digest.String())
		Expect(err).To(Succeed())
		img, err := remote.Image(artifactRef, append([]remote.Option{remote.WithContext(ctx)}, remoteOpts...)...)
		Expect(err).To(Succeed())

		manifest, err := img.Manifest()
		Expect(err).To(Succeed())
		Expect(manifest.Annotations).To(HaveKeyWithValue(image.WerfImageNameAnnotation, "my-app"))
		Expect(manifest.Annotations).To(HaveKeyWithValue(image.WerfChecksumAnnotation, "checksum-v1"))
		Expect(manifest.Annotations).To(HaveKeyWithValue(image.WerfPlatformAnnotation, "linux/amd64"))
		Expect(manifest.Config.MediaType).To(Equal(gcrtypes.MediaType(artifactType)))
		Expect(manifest.Subject).ToNot(BeNil())
		Expect(manifest.Subject.Digest.String()).To(Equal(parentDigest))
	})

	It("should deduplicate artifacts of the same type when imageName is empty", func(ctx SpecContext) {
		attach(ctx, []byte(`{"v":1}`), "")
		attach(ctx, []byte(`{"v":2}`), "")

		im := pullIndex(ctx)
		Expect(im.Manifests).To(HaveLen(1))

		store := artifact.NewOCIStore(repo, "", remoteOpts...)
		content, err := store.GetAttachedContent(ctx, parentDigest, artifactType, nil)
		Expect(err).To(Succeed())
		Expect(content).To(MatchJSON(`{"v":2}`))
	})

	It("should keep separate entries for different imageNames", func(ctx SpecContext) {
		attach(ctx, []byte(`{"img":"a"}`), "app-a")
		attach(ctx, []byte(`{"img":"b"}`), "app-b")

		im := pullIndex(ctx)
		Expect(im.Manifests).To(HaveLen(2))
	})

	It("should keep separate entries for different imageNames sharing identical payload", func(ctx SpecContext) {
		payload := []byte(`{"identical":"payload"}`)

		attach(ctx, payload, "app-a")
		attach(ctx, payload, "app-b")

		im := pullIndex(ctx)
		Expect(im.Manifests).To(HaveLen(2))
		Expect(im.Manifests[0].Digest).ToNot(Equal(im.Manifests[1].Digest))

		storeA := artifact.NewOCIStore(repo, "app-a", remoteOpts...)
		contentA, err := storeA.GetAttachedContent(ctx, parentDigest, artifactType, nil)
		Expect(err).To(Succeed())
		Expect(contentA).To(MatchJSON(`{"identical":"payload"}`))

		storeB := artifact.NewOCIStore(repo, "app-b", remoteOpts...)
		contentB, err := storeB.GetAttachedContent(ctx, parentDigest, artifactType, nil)
		Expect(err).To(Succeed())
		Expect(contentB).To(MatchJSON(`{"identical":"payload"}`))
	})

	It("should round-trip artifact content via GetAttachedContent", func(ctx SpecContext) {
		attach(ctx, []byte(`{"vex":"data"}`), "my-app")

		store := artifact.NewOCIStore(repo, "my-app", remoteOpts...)
		content, err := store.GetAttachedContent(ctx, parentDigest, artifactType, nil)
		Expect(err).To(Succeed())
		Expect(content).To(MatchJSON(`{"vex":"data"}`))
	})

	It("should retain all annotations under concurrent push", func(ctx SpecContext) {
		names := []string{"app-a", "app-b", "app-c"}
		errs := make([]error, 3)

		parallel.ForEach(names, func(name string, i int) {
			errs[i] = attachE(ctx, []byte(`{"img":"`+name+`"}`), name)
		})

		for i, name := range names {
			Expect(errs[i]).To(Succeed(), "Attach for %s should succeed", name)
		}

		im := pullIndex(ctx)
		Expect(im.Manifests).To(HaveLen(3))
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

var _ = Describe("Default registry authentication (integration)", func() {
	const (
		artifactType = "application/vnd.dsse.envelope.v1+json"
		username     = "testuser"
		password     = "testpassword"
	)

	var (
		server       *httptest.Server
		repo         string
		parentDigest string
		authOpts     []remote.Option
	)

	BeforeEach(func(ctx SpecContext) {
		server = httptest.NewServer(requireBasicAuth(registry.New(), username, password))
		host := strings.TrimPrefix(server.URL, "http://")
		repo = host + "/test/app"
		authOpts = []remote.Option{remote.WithAuth(&authn.Basic{Username: username, Password: password})}

		dockerConfigDir := GinkgoT().TempDir()
		auth := base64.StdEncoding.EncodeToString([]byte(username + ":" + password))
		configJSON := fmt.Sprintf(`{"auths":{"%s":{"auth":"%s"}}}`, host, auth)
		Expect(os.WriteFile(filepath.Join(dockerConfigDir, "config.json"), []byte(configJSON), 0o600)).To(Succeed())
		GinkgoT().Setenv("DOCKER_CONFIG", dockerConfigDir)

		Expect(docker_registry.Init(ctx, false, false, nil, nil)).To(Succeed())

		parent, err := random.Image(256, 1)
		Expect(err).To(Succeed())

		parentRef, err := name.NewTag(repo + ":v1")
		Expect(err).To(Succeed())
		Expect(remote.Write(parentRef, parent, append([]remote.Option{remote.WithContext(ctx)}, authOpts...)...)).To(Succeed())

		dgst, err := parent.Digest()
		Expect(err).To(Succeed())
		parentDigest = dgst.String()
	})

	AfterEach(func() {
		server.Close()
	})

	It("should pull artifact content via GetAttachedContentAny using default docker_registry auth", func(ctx SpecContext) {
		attacher := artifact.NewOCIStore(repo, "my-app", authOpts...)
		Expect(attacher.Attach(ctx, parentDigest, artifactType, []byte(`{"sbom":"data"}`), "", "", "")).To(Succeed())

		store := artifact.NewOCIStore(repo, "")
		content, err := store.GetAttachedContent(ctx, parentDigest, artifactType, nil)
		Expect(err).To(Succeed())
		Expect(content).To(MatchJSON(`{"sbom":"data"}`))
	})
})

func requireBasicAuth(next http.Handler, username, password string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, pass, ok := r.BasicAuth()
		if !ok || user != username || pass != password {
			w.Header().Set("WWW-Authenticate", `Basic realm="test"`)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

var _ = Describe("Attach convergence (integration)", func() {
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

	It("should restore its entry after another writer replaced the whole index", func(ctx SpecContext) {
		storeA := artifact.NewOCIStore(repo, "app-a", remoteOpts...)
		Expect(storeA.Attach(ctx, parentDigest, artifactType, []byte(`{"img":"a"}`), "", "", "")).To(Succeed())

		descA, found, err := storeA.GetAttached(ctx, parentDigest, artifactType, nil)
		Expect(err).To(Succeed())
		Expect(found).To(BeTrue())

		storeB := artifact.NewOCIStore(repo, "app-b", remoteOpts...)
		Expect(storeB.Attach(ctx, parentDigest, artifactType, []byte(`{"img":"b"}`), "", "", "")).To(Succeed())

		descB, found, err := storeB.GetAttached(ctx, parentDigest, artifactType, nil)
		Expect(err).To(Succeed())
		Expect(found).To(BeTrue())

		Expect(clobberIndex(ctx, repo, parentDigest, descB, remoteOpts)).To(Succeed())

		_, found, err = storeA.GetAttached(ctx, parentDigest, artifactType, nil)
		Expect(err).To(Succeed())
		Expect(found).To(BeFalse(), "precondition: the entry of app-a must be lost")

		Expect(storeA.Attach(ctx, parentDigest, artifactType, []byte(`{"img":"a"}`), "", "", "")).To(Succeed())

		restored, found, err := storeA.GetAttached(ctx, parentDigest, artifactType, nil)
		Expect(err).To(Succeed())
		Expect(found).To(BeTrue())
		Expect(restored.Digest).To(Equal(descA.Digest))

		kept, found, err := storeB.GetAttached(ctx, parentDigest, artifactType, nil)
		Expect(err).To(Succeed())
		Expect(found).To(BeTrue(), "the entry of app-b must survive the repair")
		Expect(kept.Digest).To(Equal(descB.Digest))
	})

	It("should replace its own previous entry instead of accumulating", func(ctx SpecContext) {
		store := artifact.NewOCIStore(repo, "app-a", remoteOpts...)

		Expect(store.Attach(ctx, parentDigest, artifactType, []byte(`{"v":1}`), "", "", "")).To(Succeed())
		Expect(store.Attach(ctx, parentDigest, artifactType, []byte(`{"v":2}`), "", "", "")).To(Succeed())

		idx, err := artifact.PullFallbackIndex(ctx, repo, parentDigest, append([]remote.Option{remote.WithContext(ctx)}, remoteOpts...)...)
		Expect(err).To(Succeed())
		im, err := idx.IndexManifest()
		Expect(err).To(Succeed())
		Expect(im.Manifests).To(HaveLen(1))

		content, err := store.GetAttachedContent(ctx, parentDigest, artifactType, nil)
		Expect(err).To(Succeed())
		Expect(content).To(MatchJSON(`{"v":2}`))
	})
})

// clobberIndex replaces the whole artifact index with a single descriptor,
// reproducing a lost update caused by a writer that read a stale index.
func clobberIndex(ctx context.Context, repo, parentDigest string, keep v1.Descriptor, remoteOpts []remote.Option) error {
	tagRef, err := name.NewTag(repo + ":" + artifact.FallbackTag(parentDigest))
	if err != nil {
		return err
	}

	raw, err := json.Marshal(&v1.IndexManifest{
		SchemaVersion: 2,
		MediaType:     gcrtypes.OCIImageIndex,
		Manifests:     []v1.Descriptor{keep},
	})
	if err != nil {
		return err
	}

	return remote.Put(tagRef, rawIndex{raw: raw}, append([]remote.Option{remote.WithContext(ctx)}, remoteOpts...)...)
}

// rawIndex publishes a hand-built index manifest verbatim.
type rawIndex struct {
	raw []byte
}

func (i rawIndex) RawManifest() ([]byte, error) {
	return i.raw, nil
}

func (i rawIndex) MediaType() (gcrtypes.MediaType, error) {
	return gcrtypes.OCIImageIndex, nil
}

var _ = Describe("Attach with an unnamed artifact (integration)", func() {
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

	It("should attach without an image name next to a named artifact", func(ctx SpecContext) {
		named := artifact.NewOCIStore(repo, "app-a", remoteOpts...)
		Expect(named.Attach(ctx, parentDigest, artifactType, []byte(`{"img":"a"}`), "", "", "")).To(Succeed())

		unnamed := artifact.NewOCIStore(repo, "", remoteOpts...)
		Expect(unnamed.Attach(ctx, parentDigest, artifactType, []byte(`{"img":""}`), "", "", "")).To(Succeed())

		idx, err := artifact.PullFallbackIndex(ctx, repo, parentDigest, append([]remote.Option{remote.WithContext(ctx)}, remoteOpts...)...)
		Expect(err).To(Succeed())
		im, err := idx.IndexManifest()
		Expect(err).To(Succeed())
		Expect(im.Manifests).To(HaveLen(2))

		content, err := named.GetAttachedContent(ctx, parentDigest, artifactType, nil)
		Expect(err).To(Succeed())
		Expect(content).To(MatchJSON(`{"img":"a"}`))
	})

	It("should replace its own unnamed entry on reattach", func(ctx SpecContext) {
		unnamed := artifact.NewOCIStore(repo, "", remoteOpts...)

		Expect(unnamed.Attach(ctx, parentDigest, artifactType, []byte(`{"v":1}`), "", "", "")).To(Succeed())
		Expect(unnamed.Attach(ctx, parentDigest, artifactType, []byte(`{"v":2}`), "", "", "")).To(Succeed())

		idx, err := artifact.PullFallbackIndex(ctx, repo, parentDigest, append([]remote.Option{remote.WithContext(ctx)}, remoteOpts...)...)
		Expect(err).To(Succeed())
		im, err := idx.IndexManifest()
		Expect(err).To(Succeed())
		Expect(im.Manifests).To(HaveLen(1))

		content, err := unnamed.GetAttachedContent(ctx, parentDigest, artifactType, nil)
		Expect(err).To(Succeed())
		Expect(content).To(MatchJSON(`{"v":2}`))
	})
})
