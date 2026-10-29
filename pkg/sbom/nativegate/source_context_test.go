package nativegate

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"

	shared "fox.flant.com/deckhouse/container-base/pm.git/sbom"
	"fox.flant.com/deckhouse/container-base/pm.git/sbom/buildcontext"
	"fox.flant.com/deckhouse/container-base/pm.git/sbom/original"
	"fox.flant.com/deckhouse/container-base/pm.git/sbom/sources"
	"github.com/google/go-containerregistry/pkg/registry"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/layout"
	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"

	"github.com/werf/werf/v3/pkg/docker_registry"
	"github.com/werf/werf/v3/pkg/sbom/shippedscope"
)

// closableOriginalRegistry hands the caller the shutdown, so that a spec can prove the
// materialized layout is read without a registry behind it.
func closableOriginalRegistry(ctx context.Context) (string, func()) {
	ginkgo.GinkgoHelper()
	gomega.Expect(docker_registry.Init(ctx, true, false, nil, nil)).To(gomega.Succeed())
	server := httptest.NewServer(registry.New())
	ginkgo.DeferCleanup(server.Close)

	return strings.TrimPrefix(server.URL, "http://"), server.Close
}

func materializationScratch() string {
	ginkgo.GinkgoHelper()
	directory, err := os.MkdirTemp("", "dk-build-context-")
	gomega.Expect(err).NotTo(gomega.HaveOccurred())
	ginkgo.DeferCleanup(func() { gomega.Expect(os.RemoveAll(directory)).To(gomega.Succeed()) })

	return directory
}

func packageIndex(index int) *int { return &index }

// materializationPacket would not survive a generic decode and re-encode: the integer
// exceeds float64 precision, and the markup is escaped rather than rewritten.
func materializationPacket(pinned string) string {
	return fmt.Sprintf(`{"name":"original","version":"1.0","arch":["linux/amd64"],"digest":%q,"license":"MIT","description":"<b>a&b</b>","opaque":9007199254740993}`, pinned)
}

func compactPacket(packet string) string {
	ginkgo.GinkgoHelper()
	var compacted bytes.Buffer
	gomega.Expect(json.Compact(&compacted, []byte(packet))).To(gomega.Succeed())

	return compacted.String()
}

func pmSubject(repo, pinned string) shared.BuildComponent {
	return shared.BuildComponent{
		ID: "package-0", Name: "original", Version: "1.0",
		Source: shared.BuildSource{Kind: "pm", Locator: repo, Checksum: pinned},
	}
}

func materializedContext(directory string) *buildcontext.Context {
	ginkgo.GinkgoHelper()
	body, err := os.ReadFile(filepath.Join(directory, materializedContextFile))
	gomega.Expect(err).NotTo(gomega.HaveOccurred())
	decoded, err := buildcontext.Decode(body)
	gomega.Expect(err).NotTo(gomega.HaveOccurred())

	return decoded
}

// exportedLayoutRoot reads a materialized layout the way the compile-time consumer
// does: the pinned digest must be the layout's own descriptor, and the image is taken
// from it through the canonical selection, never from the layout's order or tags.
func exportedLayoutRoot(directory, pinned, platform string) *original.OriginalPackage {
	ginkgo.GinkgoHelper()
	pin, err := v1.NewHash(pinned)
	gomega.Expect(err).NotTo(gomega.HaveOccurred())
	target, err := v1.ParsePlatform(platform)
	gomega.Expect(err).NotTo(gomega.HaveOccurred())

	index, err := layout.ImageIndexFromPath(directory)
	gomega.Expect(err).NotTo(gomega.HaveOccurred())
	manifest, err := index.IndexManifest()
	gomega.Expect(err).NotTo(gomega.HaveOccurred())
	gomega.Expect(manifest.Manifests).To(gomega.HaveLen(1))
	gomega.Expect(manifest.Manifests[0].Digest).To(gomega.Equal(pin))

	var image v1.Image
	if manifest.Manifests[0].MediaType.IsIndex() {
		child, err := index.ImageIndex(pin)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		image, err = original.SelectImage(child, pin, *target)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
	} else {
		image, err = index.Image(pin)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(original.ValidateImage(image, pin, *target)).To(gomega.Succeed())
	}

	pkg, err := original.NewOriginalPackage(image)
	gomega.Expect(err).NotTo(gomega.HaveOccurred())
	gomega.Expect(pkg.Complete()).To(gomega.BeTrue())

	return pkg
}

func exportedOriginalBody(pkg *original.OriginalPackage, name string) string {
	ginkgo.GinkgoHelper()
	reader, err := pkg.Open(name)
	gomega.Expect(err).NotTo(gomega.HaveOccurred())
	defer func() { gomega.Expect(reader.Close()).To(gomega.Succeed()) }()
	body, err := io.ReadAll(reader)
	gomega.Expect(err).NotTo(gomega.HaveOccurred())

	return string(body)
}

var _ = ginkgo.Describe("Materializing producer contexts", func() {
	ginkgo.It("fills a declared context with the layouts its imports are proven against", func(ctx ginkgo.SpecContext) {
		host, stop := closableOriginalRegistry(ctx)
		repo := host + "/test/original"
		pinned := pushOriginalImage(ctx, repo, "image", originalImageFixture("linux/amd64", map[string]string{
			"/usr/bin/tool":   "amd64 body",
			"/usr/share/junk": "payload nobody imported",
		}))
		packet := materializationPacket(pinned)
		declaration := &buildcontext.Context{
			Version: 1, Platform: "linux/amd64", Subject: pmSubject(repo, pinned),
			Packages: []buildcontext.Package{{Platform: "linux/amd64", Registry: repo, Packet: json.RawMessage(packet)}},
			Imports:  []buildcontext.Import{{Path: "/usr/bin/tool", Package: packageIndex(0), OriginalPath: "usr/bin/tool"}},
		}
		directory := materializationScratch()

		filename, err := MaterializeBuildContext(ctx, declaration, fixtureIndex(map[string]string{"/usr/bin/tool": "amd64 body"}), directory, MaterializeBuildContextOptions{ContainerRoot: "/dk/context"})
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(filename).To(gomega.Equal("/dk/context/context.json"))
		gomega.Expect(declaration.Packages[0].Layout).To(gomega.BeEmpty())

		written := materializedContext(directory)
		gomega.Expect(written.Subject).To(gomega.Equal(pmSubject(repo, pinned)))
		gomega.Expect(string(written.Packages[0].Packet)).To(gomega.Equal(strings.NewReplacer("<", `\u003c`, ">", `\u003e`, "&", `\u0026`).Replace(packet)))
		var fields struct {
			Description string `json:"description"`
		}
		gomega.Expect(json.Unmarshal(written.Packages[0].Packet, &fields)).To(gomega.Succeed())
		gomega.Expect(fields.Description).To(gomega.Equal("<b>a&b</b>"))
		gomega.Expect(written.Packages[0].Platform).To(gomega.Equal("linux/amd64"))
		gomega.Expect(written.Imports).To(gomega.Equal(declaration.Imports))
		gomega.Expect(written.OwnRoots).To(gomega.BeEmpty())

		layoutPath := written.Packages[0].Layout
		gomega.Expect(layoutPath).To(gomega.HavePrefix("/dk/context/originals/"))
		info, err := os.Stat(filepath.Join(directory, materializedContextFile))
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(info.Mode().Perm()).To(gomega.Equal(os.FileMode(0o444)))

		// Nothing below reaches a registry: the helpers compile and link offline.
		stop()
		pkg := exportedLayoutRoot(filepath.Join(directory, strings.TrimPrefix(layoutPath, "/dk/context/")), pinned, "linux/amd64")
		gomega.Expect(exportedOriginalBody(pkg, "usr/bin/tool")).To(gomega.Equal("amd64 body"))
	})

	ginkgo.It("keeps the pinned index as the layout root while the target platform differs from the original", func(ctx ginkgo.SpecContext) {
		host, stop := closableOriginalRegistry(ctx)
		repo := host + "/test/original"
		pinned := pushOriginalIndex(ctx, repo, "index",
			originalVariant{platform: "linux/amd64", image: originalImageFixture("linux/amd64", map[string]string{"/usr/bin/tool": "amd64 body"})},
			originalVariant{platform: "linux/arm64", image: originalImageFixture("linux/arm64", map[string]string{"/usr/bin/tool": "arm64 body"})},
		)
		declaration := &buildcontext.Context{
			Version: 1, Platform: "darwin/arm64", Subject: pmSubject(repo, pinned),
			Packages: []buildcontext.Package{{Platform: "linux/amd64", Registry: repo, Packet: json.RawMessage(originalPacket([]string{"linux/amd64", "linux/arm64"}, pinned))}},
			Imports:  []buildcontext.Import{{Path: "/usr/bin/tool", Package: packageIndex(0), OriginalPath: "usr/bin/tool"}},
		}
		directory := materializationScratch()

		_, err := MaterializeBuildContext(ctx, declaration, fixtureIndex(map[string]string{"/usr/bin/tool": "amd64 body"}), directory, MaterializeBuildContextOptions{ContainerRoot: "/dk/context"})
		gomega.Expect(err).NotTo(gomega.HaveOccurred())

		written := materializedContext(directory)
		gomega.Expect(written.Platform).To(gomega.Equal("darwin/arm64"))
		gomega.Expect(written.Packages[0].Platform).To(gomega.Equal("linux/amd64"))

		stop()
		pkg := exportedLayoutRoot(filepath.Join(directory, strings.TrimPrefix(written.Packages[0].Layout, "/dk/context/")), pinned, "linux/amd64")
		gomega.Expect(exportedOriginalBody(pkg, "usr/bin/tool")).To(gomega.Equal("amd64 body"))
	})

	ginkgo.It("exports one layout for packages that alias one pinned original", func(ctx ginkgo.SpecContext) {
		repo := originalRegistryHost(ctx) + "/test/original"
		pinned := pushOriginalImage(ctx, repo, "image", originalImageFixture("linux/amd64", map[string]string{
			"/usr/bin/tool": "amd64 body",
			"/usr/lib/one":  "library body",
		}))
		rewritten := strings.ReplaceAll(originalPacket([]string{"linux/amd64"}, pinned), ",", ", ")
		declaration := &buildcontext.Context{
			Version: 1, Platform: "linux/amd64", Subject: pmSubject(repo, pinned),
			Packages: []buildcontext.Package{
				{Platform: "linux/amd64", Registry: repo, Packet: json.RawMessage(originalPacket([]string{"linux/amd64"}, pinned))},
				{Platform: "linux/amd64", Registry: repo, Packet: json.RawMessage(rewritten)},
			},
			Imports: []buildcontext.Import{
				{Path: "/usr/bin/tool", Package: packageIndex(0), OriginalPath: "usr/bin/tool"},
				{Path: "/usr/lib/one", Package: packageIndex(1), OriginalPath: "usr/lib/one"},
			},
		}
		directory := materializationScratch()

		_, err := MaterializeBuildContext(ctx, declaration, fixtureIndex(map[string]string{"/usr/bin/tool": "amd64 body", "/usr/lib/one": "library body"}), directory, MaterializeBuildContextOptions{ContainerRoot: "/dk/context"})
		gomega.Expect(err).NotTo(gomega.HaveOccurred())

		written := materializedContext(directory)
		gomega.Expect(written.Packages[1].Layout).To(gomega.Equal(written.Packages[0].Layout))
		gomega.Expect(string(written.Packages[1].Packet)).To(gomega.Equal(compactPacket(rewritten)))
		exported, err := os.ReadDir(filepath.Join(directory, materializedOriginalsDir))
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(exported).To(gomega.HaveLen(1))
		// One descriptor: a second export of one identity would leave the consumer with
		// a duplicate to choose between.
		pkg := exportedLayoutRoot(filepath.Join(directory, strings.TrimPrefix(written.Packages[0].Layout, "/dk/context/")), pinned, "linux/amd64")
		gomega.Expect(exportedOriginalBody(pkg, "usr/lib/one")).To(gomega.Equal("library body"))
	})

	ginkgo.It("derives the imports from the actual stage snapshots", func(ctx ginkgo.SpecContext) {
		repo := originalRegistryHost(ctx) + "/test/original"
		pinned := pushOriginalImage(ctx, repo, "image", originalImageFixture("linux/amd64", map[string]string{
			"/src/one.c":    "one body",
			"/src/unused.c": "payload no import carried",
		}))
		packet := originalPacket([]string{"linux/amd64"}, pinned)
		declaration := &buildcontext.Context{
			Version: 1, Platform: "linux/amd64", Subject: pmSubject(repo, pinned),
			Packages: []buildcontext.Package{{Platform: "linux/amd64", Registry: repo, Packet: json.RawMessage(packet)}},
			Imports:  []buildcontext.Import{},
		}
		target := fixtureIndex(map[string]string{"/bin/sh": "shell", "/work/one.c": "one body"})
		snapshots := []SourceSnapshot{
			{Stage: "from", Index: fixtureIndex(map[string]string{"/bin/sh": "shell"})},
			{Stage: "install", Index: target, Imports: []SourceImport{{
				Index:   fixtureIndex(map[string]string{"/src/one.c": "one body", "/src/unused.c": "payload no import carried"}),
				Receipt: &sources.Receipt{Version: sources.Version, Sources: []sources.Source{{Registry: repo, Platform: "linux/amd64", Packet: json.RawMessage(packet)}}},
				Scope:   ImportScope{FromPath: "/src", ToPath: "/work", IncludePaths: []string{"one.c"}},
			}}},
		}
		directory := materializationScratch()

		_, err := MaterializeBuildContext(ctx, declaration, target, directory, MaterializeBuildContextOptions{ContainerRoot: "/dk/context", Snapshots: snapshots})
		gomega.Expect(err).NotTo(gomega.HaveOccurred())

		written := materializedContext(directory)
		gomega.Expect(written.Imports).To(gomega.Equal([]buildcontext.Import{{Path: "/work/one.c", Package: packageIndex(0), OriginalPath: "src/one.c"}}))
		gomega.Expect(declaration.Imports).To(gomega.BeEmpty())
	})

	ginkgo.It("refuses snapshots whose last stage is not the observed target", func(ctx ginkgo.SpecContext) {
		repo := originalRegistryHost(ctx) + "/test/original"
		pinned := pushOriginalImage(ctx, repo, "image", originalImageFixture("linux/amd64", map[string]string{"/src/one.c": "one body"}))
		declaration := fixtureDeclaration(repo, pinned)
		directory := materializationScratch()

		_, err := MaterializeBuildContext(ctx, declaration, fixtureIndex(map[string]string{"/work/one.c": "one body"}), directory,
			MaterializeBuildContextOptions{ContainerRoot: "/dk/context", Snapshots: []SourceSnapshot{{Stage: "install", Index: fixtureIndex(map[string]string{"/work/one.c": "other body"})}}})
		gomega.Expect(err).To(gomega.MatchError(gomega.ContainSubstring(`no-data: stage "install" is not the target the observed index was taken from`)))

		left, readErr := os.ReadDir(directory)
		gomega.Expect(readErr).NotTo(gomega.HaveOccurred())
		gomega.Expect(left).To(gomega.BeEmpty())
	})

	ginkgo.It("refuses a declared mapping beside the snapshots it would derive", func(ctx ginkgo.SpecContext) {
		declaration := fixtureDeclaration("example.test/original", "sha256:"+strings.Repeat("a", 64),
			buildcontext.Import{Path: "/usr/bin/tool", Package: packageIndex(0), OriginalPath: "usr/bin/tool"})
		target := fixtureIndex(map[string]string{"/usr/bin/tool": "amd64 body"})

		_, err := MaterializeBuildContext(ctx, declaration, target, materializationScratch(),
			MaterializeBuildContextOptions{ContainerRoot: "/dk/context", Snapshots: []SourceSnapshot{{Stage: "install", Index: target}}})
		gomega.Expect(err).To(gomega.MatchError(gomega.ContainSubstring("invalid: imports derived from the stage snapshots leave no room for 1 declared ones")))
	})

	ginkgo.It("refuses a declaration the public codec rejects before reaching a registry", func(ctx ginkgo.SpecContext) {
		declaration := fixtureDeclaration("example.test/original", "sha256:"+strings.Repeat("a", 64))
		declaration.Imports = nil
		directory := materializationScratch()

		_, err := MaterializeBuildContext(ctx, declaration, fixtureIndex(map[string]string{"/usr/bin/tool": "amd64 body"}), directory, MaterializeBuildContextOptions{ContainerRoot: "/dk/context"})
		gomega.Expect(err).To(gomega.MatchError(gomega.ContainSubstring("requires packages and imports, including explicit empty arrays")))

		left, readErr := os.ReadDir(directory)
		gomega.Expect(readErr).NotTo(gomega.HaveOccurred())
		gomega.Expect(left).To(gomega.BeEmpty())
	})

	ginkgo.It("exports no layout for an original without its pinned manifest", func() {
		directory := filepath.Join(materializationScratch(), "layout")

		gomega.Expect(exportOriginalLayout(directory, &resolvedSource{ID: "pm-source:" + digest([]byte("unresolved"))})).
			To(gomega.MatchError(gomega.ContainSubstring("carries no verified pinned manifest")))
		gomega.Expect(os.Stat(directory)).Error().To(gomega.MatchError(os.ErrNotExist))
	})

	ginkgo.DescribeTable("refuses to write a context it cannot prove", func(ctx ginkgo.SpecContext, build func(repo, pinned string) (*buildcontext.Context, *shippedscope.FileIndex), expected string) {
		repo := originalRegistryHost(ctx) + "/test/original"
		pinned := pushOriginalImage(ctx, repo, "image", originalImageFixture("linux/amd64", map[string]string{"/usr/bin/tool": "amd64 body"}))
		declaration, observed := build(repo, pinned)
		directory := materializationScratch()

		_, err := MaterializeBuildContext(ctx, declaration, observed, directory, MaterializeBuildContextOptions{ContainerRoot: "/dk/context"})
		gomega.Expect(err).To(gomega.MatchError(gomega.ContainSubstring(expected)))

		left, readErr := os.ReadDir(directory)
		gomega.Expect(readErr).NotTo(gomega.HaveOccurred())
		gomega.Expect(left).To(gomega.BeEmpty())
	},
		ginkgo.Entry("the stage shipped other bytes at an imported path", func(repo, pinned string) (*buildcontext.Context, *shippedscope.FileIndex) {
			return fixtureDeclaration(repo, pinned, buildcontext.Import{Path: "/usr/bin/tool", Package: packageIndex(0), OriginalPath: "usr/bin/tool"}),
				fixtureIndex(map[string]string{"/usr/bin/tool": "replaced body"})
		}, "the original no longer holds the expected bytes"),
		ginkgo.Entry("an imported path the stage never shipped", func(repo, pinned string) (*buildcontext.Context, *shippedscope.FileIndex) {
			return fixtureDeclaration(repo, pinned, buildcontext.Import{Path: "/usr/bin/other", Package: packageIndex(0), OriginalPath: "usr/bin/tool"}),
				fixtureIndex(map[string]string{"/usr/bin/tool": "amd64 body"})
		}, "/usr/bin/other: the stage shipped no regular file here"),
		ginkgo.Entry("an imported path the stage shipped as a symlink", func(repo, pinned string) (*buildcontext.Context, *shippedscope.FileIndex) {
			return fixtureDeclaration(repo, pinned, buildcontext.Import{Path: "/usr/bin/tool", Package: packageIndex(0), OriginalPath: "usr/bin/tool"}),
				&shippedscope.FileIndex{Files: map[string]shippedscope.File{}, Symlinks: map[string]string{"/usr/bin/tool": "/usr/bin/real"}}
		}, "the stage shipped a symlink here"),
		ginkgo.Entry("two mappings for one destination", func(repo, pinned string) (*buildcontext.Context, *shippedscope.FileIndex) {
			return fixtureDeclaration(repo, pinned,
					buildcontext.Import{Path: "/usr/bin/tool", Package: packageIndex(0), OriginalPath: "usr/bin/tool"},
					buildcontext.Import{Path: "/usr/bin/tool", Package: packageIndex(0), OriginalPath: "usr/bin/tool"}),
				fixtureIndex(map[string]string{"/usr/bin/tool": "amd64 body"})
		}, "/usr/bin/tool: ambiguous import mapping"),
		ginkgo.Entry("an original path leaving the package root", func(repo, pinned string) (*buildcontext.Context, *shippedscope.FileIndex) {
			return fixtureDeclaration(repo, pinned, buildcontext.Import{Path: "/usr/bin/tool", Package: packageIndex(0), OriginalPath: "../etc/shadow"}),
				fixtureIndex(map[string]string{"/usr/bin/tool": "amd64 body"})
		}, `invalid original package path "../etc/shadow"`),
		ginkgo.Entry("an import index outside the declared packages", func(repo, pinned string) (*buildcontext.Context, *shippedscope.FileIndex) {
			return fixtureDeclaration(repo, pinned, buildcontext.Import{Path: "/usr/bin/tool", Package: packageIndex(1), OriginalPath: "usr/bin/tool"}),
				fixtureIndex(map[string]string{"/usr/bin/tool": "amd64 body"})
		}, "invalid or missing package index"),
		ginkgo.Entry("an unsupported target platform", func(repo, pinned string) (*buildcontext.Context, *shippedscope.FileIndex) {
			declaration := fixtureDeclaration(repo, pinned, buildcontext.Import{Path: "/usr/bin/tool", Package: packageIndex(0), OriginalPath: "usr/bin/tool"})
			declaration.Platform = "plan9/amd64"

			return declaration, fixtureIndex(map[string]string{"/usr/bin/tool": "amd64 body"})
		}, `unsupported target platform "plan9/amd64"`),
		ginkgo.Entry("a subject that is not the pinned package", func(repo, pinned string) (*buildcontext.Context, *shippedscope.FileIndex) {
			declaration := fixtureDeclaration(repo, pinned, buildcontext.Import{Path: "/usr/bin/tool", Package: packageIndex(0), OriginalPath: "usr/bin/tool"})
			declaration.Subject.Version = "2.0"

			return declaration, fixtureIndex(map[string]string{"/usr/bin/tool": "amd64 body"})
		}, "pm subject has no matching pinned package identity"),
	)

	ginkgo.It("refuses a container root the namespace cannot read", func(ctx ginkgo.SpecContext) {
		_, err := MaterializeBuildContext(ctx, &buildcontext.Context{Version: 1}, &shippedscope.FileIndex{Files: map[string]shippedscope.File{}}, materializationScratch(), MaterializeBuildContextOptions{ContainerRoot: "dk/context"})
		gomega.Expect(err).To(gomega.MatchError(gomega.ContainSubstring(`container root path "dk/context"`)))
	})

	ginkgo.It("refuses a scratch directory that already holds something", func(ctx ginkgo.SpecContext) {
		directory := materializationScratch()
		gomega.Expect(os.WriteFile(filepath.Join(directory, materializedContextFile), []byte("{}"), 0o644)).To(gomega.Succeed())

		_, err := MaterializeBuildContext(ctx, &buildcontext.Context{Version: 1}, &shippedscope.FileIndex{Files: map[string]shippedscope.File{}}, directory, MaterializeBuildContextOptions{ContainerRoot: "/dk/context"})
		gomega.Expect(err).To(gomega.MatchError(gomega.ContainSubstring("materialized into an empty caller-owned directory")))
		gomega.Expect(os.ReadFile(filepath.Join(directory, materializedContextFile))).To(gomega.Equal([]byte("{}")))
	})

	ginkgo.It("refuses an incomplete observed index", func(ctx ginkgo.SpecContext) {
		_, err := MaterializeBuildContext(ctx, &buildcontext.Context{Version: 1}, &shippedscope.FileIndex{Files: map[string]shippedscope.File{}, Incomplete: true}, materializationScratch(), MaterializeBuildContextOptions{ContainerRoot: "/dk/context"})
		gomega.Expect(err).To(gomega.MatchError(gomega.ContainSubstring("no-data: materializing a build context needs the complete observed file index")))
	})
})

func fixtureDeclaration(repo, pinned string, imports ...buildcontext.Import) *buildcontext.Context {
	return &buildcontext.Context{
		Version: 1, Platform: "linux/amd64", Subject: pmSubject(repo, pinned),
		Packages: []buildcontext.Package{{Platform: "linux/amd64", Registry: repo, Packet: json.RawMessage(originalPacket([]string{"linux/amd64"}, pinned))}},
		Imports:  append([]buildcontext.Import{}, imports...),
	}
}
