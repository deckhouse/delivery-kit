package nativegate

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http/httptest"
	"strings"

	"fox.flant.com/deckhouse/container-base/pm.git/sbom/sources"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/registry"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/types"
	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"

	"github.com/werf/werf/v3/pkg/docker_registry"
)

type originalVariant struct {
	platform string
	image    v1.Image
}

type rawOriginalManifest struct {
	body      []byte
	mediaType types.MediaType
}

func (m rawOriginalManifest) RawManifest() ([]byte, error) { return m.body, nil }

func (m rawOriginalManifest) MediaType() (types.MediaType, error) { return m.mediaType, nil }

func originalRegistryHost(ctx context.Context) string {
	ginkgo.GinkgoHelper()
	gomega.Expect(docker_registry.Init(ctx, true, false, nil, nil)).To(gomega.Succeed())
	server := httptest.NewServer(registry.New())
	ginkgo.DeferCleanup(server.Close)
	return strings.TrimPrefix(server.URL, "http://")
}

func originalImageFixture(platform string, files map[string]string) v1.Image {
	ginkgo.GinkgoHelper()
	target, err := v1.ParsePlatform(platform)
	gomega.Expect(err).NotTo(gomega.HaveOccurred())
	image := fixtureImage(files)
	config, err := image.ConfigFile()
	gomega.Expect(err).NotTo(gomega.HaveOccurred())
	config.OS, config.Architecture, config.Variant = target.OS, target.Architecture, target.Variant
	image, err = mutate.ConfigFile(image, config)
	gomega.Expect(err).NotTo(gomega.HaveOccurred())
	return image
}

func pushOriginalImage(ctx context.Context, repo, tag string, image v1.Image) string {
	ginkgo.GinkgoHelper()
	ref, err := name.NewTag(repo + ":" + tag)
	gomega.Expect(err).NotTo(gomega.HaveOccurred())
	gomega.Expect(remote.Write(ref, image, remote.WithContext(ctx))).To(gomega.Succeed())
	hash, err := image.Digest()
	gomega.Expect(err).NotTo(gomega.HaveOccurred())
	return hash.String()
}

func pushOriginalIndex(ctx context.Context, repo, tag string, variants ...originalVariant) string {
	ginkgo.GinkgoHelper()
	index := mutate.IndexMediaType(empty.Index, types.OCIImageIndex)
	for _, variant := range variants {
		target, err := v1.ParsePlatform(variant.platform)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		index = mutate.AppendManifests(index, mutate.IndexAddendum{Add: variant.image, Descriptor: v1.Descriptor{Platform: target}})
	}
	ref, err := name.NewTag(repo + ":" + tag)
	gomega.Expect(err).NotTo(gomega.HaveOccurred())
	gomega.Expect(remote.WriteIndex(ref, index, remote.WithContext(ctx))).To(gomega.Succeed())
	hash, err := index.Digest()
	gomega.Expect(err).NotTo(gomega.HaveOccurred())
	return hash.String()
}

// The opaque token exceeds float64 precision, so a Packet that traveled through a
// generic decoder and back would not come out of the resolver unchanged.
func originalPacket(arch []string, pinned string) string {
	ginkgo.GinkgoHelper()
	declared, err := json.Marshal(arch)
	gomega.Expect(err).NotTo(gomega.HaveOccurred())
	return fmt.Sprintf(`{"name":"original","version":"1.0","arch":%s,"digest":%q,"license":"MIT","opaque":9007199254740993}`, declared, pinned)
}

func originalFileBody(pkg *resolvedSource, path string) string {
	ginkgo.GinkgoHelper()
	reader, err := pkg.Original.Open(path)
	gomega.Expect(err).NotTo(gomega.HaveOccurred())
	defer func() { gomega.Expect(reader.Close()).To(gomega.Succeed()) }()
	body, err := io.ReadAll(reader)
	gomega.Expect(err).NotTo(gomega.HaveOccurred())
	return string(body)
}

var _ = ginkgo.Describe("pinned original source resolution", func() {
	ginkgo.It("binds a source pinned directly to an image manifest", func(ctx ginkgo.SpecContext) {
		repo := originalRegistryHost(ctx) + "/test/original"
		image := originalImageFixture("linux/amd64", map[string]string{"/usr/bin/tool": "amd64 body"})
		pinned := pushOriginalImage(ctx, repo, "image", image)
		packet := originalPacket([]string{"linux/amd64", "linux/arm64"}, pinned)

		resolved, err := resolveOriginalSource(ctx, sources.Source{Registry: repo, Packet: json.RawMessage(packet), Platform: "linux/amd64"})
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(resolved.Package.Name).To(gomega.Equal("original"))
		gomega.Expect(resolved.Package.Version).To(gomega.Equal("1.0"))
		gomega.Expect(resolved.Package.License).To(gomega.Equal("MIT"))
		gomega.Expect(resolved.Package.Arch).To(gomega.Equal([]string{"linux/amd64", "linux/arm64"}))
		gomega.Expect(string(resolved.Source.Packet)).To(gomega.Equal(packet))
		gomega.Expect(resolved.Original.Complete()).To(gomega.BeTrue())
		gomega.Expect(originalFileBody(resolved, "usr/bin/tool")).To(gomega.Equal("amd64 body"))
		gomega.Expect(resolved.ID).To(gomega.Equal("pm-source:" + digest([]byte(repo+"\n"+pinned+"\nlinux/amd64"))))
	})

	ginkgo.It("selects the one index descendant the platform names", func(ctx ginkgo.SpecContext) {
		repo := originalRegistryHost(ctx) + "/test/original"
		pinned := pushOriginalIndex(ctx, repo, "index",
			originalVariant{platform: "linux/amd64", image: originalImageFixture("linux/amd64", map[string]string{"/usr/bin/tool": "amd64 body"})},
			originalVariant{platform: "linux/arm64", image: originalImageFixture("linux/arm64", map[string]string{"/usr/bin/tool": "arm64 body"})},
		)
		packet := originalPacket([]string{"linux/amd64", "linux/arm64"}, pinned)
		entry := sources.Source{Registry: repo, Packet: json.RawMessage(packet), Platform: "linux/amd64"}

		resolved, err := resolveOriginalSource(ctx, entry)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(originalFileBody(resolved, "usr/bin/tool")).To(gomega.Equal("amd64 body"))

		entry.Platform = "linux/arm64"
		other, err := resolveOriginalSource(ctx, entry)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(originalFileBody(other, "usr/bin/tool")).To(gomega.Equal("arm64 body"))
		gomega.Expect(other.ID).NotTo(gomega.Equal(resolved.ID))
	})

	ginkgo.It("keeps one identity for one original across receipt rewrites", func(ctx ginkgo.SpecContext) {
		host := originalRegistryHost(ctx)
		repo := host + "/test/original"
		image := originalImageFixture("linux/amd64", map[string]string{"/usr/bin/tool": "amd64 body"})
		pinned := pushOriginalImage(ctx, repo, "image", image)

		resolved, err := resolveOriginalSource(ctx, sources.Source{Registry: repo, Packet: json.RawMessage(originalPacket([]string{"linux/amd64"}, pinned)), Platform: "linux/amd64"})
		gomega.Expect(err).NotTo(gomega.HaveOccurred())

		rewritten := fmt.Sprintf("{\n  \"name\": \"original\",\n  \"version\": \"1.0\",\n  \"arch\": [\"linux/amd64\"],\n  \"digest\": %q,\n  \"license\": \"MIT\",\n  \"notes\": \"rebuilt\"\n}", pinned)
		again, err := resolveOriginalSource(ctx, sources.Source{Registry: repo, Packet: json.RawMessage(rewritten), Platform: "linux/amd64"})
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(again.ID).To(gomega.Equal(resolved.ID))
		gomega.Expect(string(again.Source.Packet)).To(gomega.Equal(rewritten))

		elsewhere := host + "/test/mirror"
		gomega.Expect(pushOriginalImage(ctx, elsewhere, "image", image)).To(gomega.Equal(pinned))
		copied, err := resolveOriginalSource(ctx, sources.Source{Registry: elsewhere, Packet: json.RawMessage(originalPacket([]string{"linux/amd64"}, pinned)), Platform: "linux/amd64"})
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(copied.ID).NotTo(gomega.Equal(resolved.ID))

		other := originalImageFixture("linux/amd64", map[string]string{"/usr/bin/tool": "other body"})
		otherPin := pushOriginalImage(ctx, repo, "other", other)
		changed, err := resolveOriginalSource(ctx, sources.Source{Registry: repo, Packet: json.RawMessage(originalPacket([]string{"linux/amd64"}, otherPin)), Platform: "linux/amd64"})
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(changed.ID).NotTo(gomega.Equal(resolved.ID))
	})

	ginkgo.It("refuses an index that leaves the platform match open", func(ctx ginkgo.SpecContext) {
		repo := originalRegistryHost(ctx) + "/test/original"
		pinned := pushOriginalIndex(ctx, repo, "index",
			originalVariant{platform: "linux/amd64", image: originalImageFixture("linux/amd64", map[string]string{"/usr/bin/tool": "first body"})},
			originalVariant{platform: "linux/amd64", image: originalImageFixture("linux/amd64", map[string]string{"/usr/bin/tool": "second body"})},
		)

		_, err := resolveOriginalSource(ctx, sources.Source{Registry: repo, Packet: json.RawMessage(originalPacket([]string{"linux/amd64"}, pinned)), Platform: "linux/amd64"})
		gomega.Expect(err).To(gomega.MatchError(gomega.ContainSubstring("ambiguous platform linux/amd64")))
	})

	ginkgo.It("refuses an image whose own platform is not the pinned target", func(ctx ginkgo.SpecContext) {
		repo := originalRegistryHost(ctx) + "/test/original"
		pinned := pushOriginalImage(ctx, repo, "image", originalImageFixture("linux/arm64", map[string]string{"/usr/bin/tool": "arm64 body"}))

		_, err := resolveOriginalSource(ctx, sources.Source{Registry: repo, Packet: json.RawMessage(originalPacket([]string{"linux/amd64"}, pinned)), Platform: "linux/amd64"})
		gomega.Expect(err).To(gomega.MatchError(gomega.ContainSubstring("does not match linux/amd64")))
	})

	ginkgo.It("refuses a pin the repository does not hold", func(ctx ginkgo.SpecContext) {
		repo := originalRegistryHost(ctx) + "/test/original"
		dangling, err := originalImageFixture("linux/amd64", map[string]string{"/usr/bin/tool": "never pushed"}).Digest()
		gomega.Expect(err).NotTo(gomega.HaveOccurred())

		_, err = resolveOriginalSource(ctx, sources.Source{Registry: repo, Packet: json.RawMessage(originalPacket([]string{"linux/amd64"}, dangling.String())), Platform: "linux/amd64"})
		gomega.Expect(err).To(gomega.MatchError(gomega.ContainSubstring("no-data: original " + repo + "@" + dangling.String())))
	})

	ginkgo.It("refuses a pinned manifest that is neither an image nor an index", func(ctx ginkgo.SpecContext) {
		repo := originalRegistryHost(ctx) + "/test/original"
		manifest := rawOriginalManifest{
			body:      []byte(`{"schemaVersion":2,"mediaType":"application/vnd.example.thing.v1+json","artifactType":"application/vnd.example.thing","blobs":[]}`),
			mediaType: types.MediaType("application/vnd.example.thing.v1+json"),
		}
		ref, err := name.NewTag(repo + ":thing")
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(remote.Put(ref, manifest, remote.WithContext(ctx))).To(gomega.Succeed())
		pinned := digest(manifest.body)

		_, err = resolveOriginalSource(ctx, sources.Source{Registry: repo, Packet: json.RawMessage(originalPacket([]string{"linux/amd64"}, pinned)), Platform: "linux/amd64"})
		gomega.Expect(err).To(gomega.MatchError(gomega.ContainSubstring("unsupported media type application/vnd.example.thing.v1+json")))
	})

	ginkgo.DescribeTable("rejects a source entry that pins nothing resolvable, without reaching a registry", func(ctx ginkgo.SpecContext, registryName, platform, packet string) {
		_, err := resolveOriginalSource(ctx, sources.Source{Registry: registryName, Packet: json.RawMessage(packet), Platform: platform})
		gomega.Expect(err).To(gomega.HaveOccurred())
		gomega.Expect(err.Error()).NotTo(gomega.ContainSubstring("no-data"))
	},
		ginkgo.Entry("undeclared architecture", "example.test/original", "linux/amd64", originalPacket(nil, "sha256:"+strings.Repeat("a", 64))),
		ginkgo.Entry("case-folded architecture", "example.test/original", "linux/amd64", originalPacket([]string{"linux/AMD64"}, "sha256:"+strings.Repeat("a", 64))),
		ginkgo.Entry("architecture declared for another platform", "example.test/original", "linux/amd64", originalPacket([]string{"linux/arm64"}, "sha256:"+strings.Repeat("a", 64))),
		ginkgo.Entry("platform without an architecture", "example.test/original", "linux", originalPacket([]string{"linux"}, "sha256:"+strings.Repeat("a", 64))),
		ginkgo.Entry("platform carrying an os version", "example.test/original", "linux/amd64:5.15", originalPacket([]string{"linux/amd64:5.15"}, "sha256:"+strings.Repeat("a", 64))),
		ginkgo.Entry("padded platform", "example.test/original", " linux/amd64", originalPacket([]string{"linux/amd64"}, "sha256:"+strings.Repeat("a", 64))),
		ginkgo.Entry("digest that is not sha256 hex", "example.test/original", "linux/amd64", originalPacket([]string{"linux/amd64"}, "sha256:deadbeef")),
		ginkgo.Entry("digest without an algorithm", "example.test/original", "linux/amd64", originalPacket([]string{"linux/amd64"}, strings.Repeat("a", 64))),
		ginkgo.Entry("registry without a host", "example/original", "linux/amd64", originalPacket([]string{"linux/amd64"}, "sha256:"+strings.Repeat("a", 64))),
		ginkgo.Entry("registry with a tag", "example.test/original:latest", "linux/amd64", originalPacket([]string{"linux/amd64"}, "sha256:"+strings.Repeat("a", 64))),
		ginkgo.Entry("registry carrying credentials", "user:secret@example.test/original", "linux/amd64", originalPacket([]string{"linux/amd64"}, "sha256:"+strings.Repeat("a", 64))),
		ginkgo.Entry("registry that is not canonical", "example.test/Original", "linux/amd64", originalPacket([]string{"linux/amd64"}, "sha256:"+strings.Repeat("a", 64))),
		ginkgo.Entry("registry host that normalizes elsewhere", "docker.io/library/original", "linux/amd64", originalPacket([]string{"linux/amd64"}, "sha256:"+strings.Repeat("a", 64))),
	)
})
