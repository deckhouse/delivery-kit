package artifact_test

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
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
	"github.com/werf/werf/v3/pkg/oci/artifact"
)

var _ = Describe("ListUnregenerableArtifacts (integration)", func() {
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

	It("should report nothing for a digest without artifacts", func(ctx SpecContext) {
		Expect(artifact.ListUnregenerableArtifacts(ctx, repo, parentDigest, remoteOpts...)).To(BeEmpty())
	})

	It("should not report artifacts a build regenerates", func(ctx SpecContext) {
		store := artifact.NewOCIStore(repo, "app", remoteOpts...)
		Expect(store.Attach(ctx, parentDigest, attestation.DSSEMediaType, []byte(`{"sbom":true}`), "checksum-sbom", "linux/amd64", "https://cyclonedx.org/bom")).To(Succeed())

		Expect(artifact.ListUnregenerableArtifacts(ctx, repo, parentDigest, remoteOpts...)).To(BeEmpty())
	})

	It("should report an attestation signed outside the build", func(ctx SpecContext) {
		store := artifact.NewOCIStore(repo, "app", remoteOpts...)
		Expect(store.Attach(ctx, parentDigest, attestation.DSSEMediaType, []byte(`{"sbom":true}`), "checksum-sbom", "", "https://cyclonedx.org/bom")).To(Succeed())
		Expect(store.Attach(ctx, parentDigest, attestation.DSSEMediaType, []byte(`{"custom":true}`), "", "", "https://example.com/predicate/v1")).To(Succeed())

		idx, err := artifact.PullFallbackIndex(ctx, repo, parentDigest, remoteOpts...)
		Expect(err).To(Succeed())
		im, err := idx.IndexManifest()
		Expect(err).To(Succeed())
		Expect(im.Manifests).To(HaveLen(2), "both artifacts must coexist for this spec to discriminate")

		Expect(artifact.ListUnregenerableArtifacts(ctx, repo, parentDigest, remoteOpts...)).To(ConsistOf("https://example.com/predicate/v1"))
	})
})

var _ = Describe("ListUnregenerableArtifacts against an authenticated registry", func() {
	const (
		username = "werf"
		password = "s3cret"
	)

	It("should authenticate with the configured registry credentials when the caller supplies none", func(ctx SpecContext) {
		upstream := registry.New()
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			user, pass, ok := r.BasicAuth()
			if !ok || user != username || pass != password {
				w.Header().Set("WWW-Authenticate", `Basic realm="registry"`)
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			upstream.ServeHTTP(w, r)
		}))
		DeferCleanup(server.Close)

		host := strings.TrimPrefix(server.URL, "http://")
		repo := host + "/test/app"
		authOpts := []remote.Option{remote.WithAuth(&authn.Basic{Username: username, Password: password})}

		parent, err := random.Image(256, 1)
		Expect(err).To(Succeed())
		parentRef, err := name.NewTag(repo + ":v1")
		Expect(err).To(Succeed())
		Expect(remote.Write(parentRef, parent, append([]remote.Option{remote.WithContext(ctx)}, authOpts...)...)).To(Succeed())
		dgst, err := parent.Digest()
		Expect(err).To(Succeed())

		store := artifact.NewOCIStore(repo, "app", authOpts...)
		Expect(store.Attach(ctx, dgst.String(), attestation.DSSEMediaType, []byte(`{"custom":true}`), "", "", "https://example.com/predicate/v1")).To(Succeed())

		dockerConfig := GinkgoT().TempDir()
		auth := base64.StdEncoding.EncodeToString([]byte(username + ":" + password))
		Expect(os.WriteFile(
			filepath.Join(dockerConfig, "config.json"),
			[]byte(fmt.Sprintf(`{"auths":{%q:{"auth":%q}}}`, host, auth)),
			0o600,
		)).To(Succeed())
		GinkgoT().Setenv("DOCKER_CONFIG", dockerConfig)

		Expect(docker_registry.Init(ctx, false, false, nil, []string{host})).To(Succeed())

		Expect(artifact.ListUnregenerableArtifacts(ctx, repo, dgst.String())).To(ConsistOf("https://example.com/predicate/v1"))
	})
})
