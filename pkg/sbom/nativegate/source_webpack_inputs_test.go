package nativegate

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	shared "fox.flant.com/deckhouse/container-base/pm.git/sbom"
	"fox.flant.com/deckhouse/container-base/pm.git/sbom/buildcontext"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"
)

// webpackComponentID spells the identity the resolver pins the original by, so a spec
// can state the manifest's component names without reading them back from it.
func webpackComponentID(repo, pinned, platform string) string {
	ginkgo.GinkgoHelper()
	pin, err := v1.NewHash(pinned)
	gomega.Expect(err).NotTo(gomega.HaveOccurred())
	target, err := v1.ParsePlatform(platform)
	gomega.Expect(err).NotTo(gomega.HaveOccurred())

	return originalSourceID(repo, pin, *target)
}

func materializedWebpackOriginals(directory string) string {
	ginkgo.GinkgoHelper()
	body, err := os.ReadFile(filepath.Join(directory, materializedWebpackFile))
	gomega.Expect(err).NotTo(gomega.HaveOccurred())

	return string(body)
}

var _ = ginkgo.Describe("Materializing webpack source evidence", func() {
	ginkgo.It("names only the imports it proved, by the pm identity they came from", func(ctx ginkgo.SpecContext) {
		repo := originalRegistryHost(ctx) + "/test/original"
		pinned := pushOriginalImage(ctx, repo, "image", originalImageFixture("linux/amd64", map[string]string{
			"/ui/actual.ts":  "actual body",
			"/ui/helper.ts":  "helper body",
			"/ui/unused.ts":  "payload no import carried",
			"/usr/share/doc": "unrelated",
		}))
		declaration := fixtureDeclaration(repo, pinned,
			buildcontext.Import{Path: "/ui/helper.ts", Package: packageIndex(0), OriginalPath: "ui/helper.ts"},
			buildcontext.Import{Path: "/ui/actual.ts", Package: packageIndex(0), OriginalPath: "ui/actual.ts"},
		)
		observed := fixtureIndex(map[string]string{"/ui/actual.ts": "actual body", "/ui/helper.ts": "helper body"})
		directory := materializationScratch()

		_, err := MaterializeBuildContext(ctx, declaration, observed, directory, MaterializeBuildContextOptions{ContainerRoot: "/dk/context", WebpackSources: true})
		gomega.Expect(err).NotTo(gomega.HaveOccurred())

		component := webpackComponentID(repo, pinned, "linux/amd64")
		gomega.Expect(materializedWebpackOriginals(directory)).To(gomega.Equal(fmt.Sprintf(
			`{"version":1,"components":[{"id":%q,"name":"original","version":"1.0","source":{"kind":"pm","locator":%q,"checksum":%q}}],"files":[{"path":"/ui/actual.ts","sha256":%q,"component":%q},{"path":"/ui/helper.ts","sha256":%q,"component":%q}]}`,
			component, repo, pinned,
			digest([]byte("actual body")), component,
			digest([]byte("helper body")), component)))

		info, err := os.Stat(filepath.Join(directory, materializedWebpackFile))
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(info.Mode().Perm()).To(gomega.Equal(os.FileMode(0o444)))
		// The context the helpers read is what it was without the manifest beside it.
		gomega.Expect(materializedContext(directory).Imports).To(gomega.Equal(declaration.Imports))
	})

	ginkgo.It("holds one component for the packages that alias one pinned original", func(ctx ginkgo.SpecContext) {
		repo := originalRegistryHost(ctx) + "/test/original"
		pinned := pushOriginalImage(ctx, repo, "image", originalImageFixture("linux/amd64", map[string]string{
			"/ui/actual.ts": "actual body",
			"/ui/helper.ts": "helper body",
		}))
		declaration := fixtureDeclaration(repo, pinned,
			buildcontext.Import{Path: "/ui/actual.ts", Package: packageIndex(0), OriginalPath: "ui/actual.ts"},
			buildcontext.Import{Path: "/ui/helper.ts", Package: packageIndex(1), OriginalPath: "ui/helper.ts"},
		)
		declaration.Packages = append(declaration.Packages, buildcontext.Package{
			Platform: "linux/amd64", Registry: repo,
			Packet: json.RawMessage(originalPacket([]string{"linux/amd64"}, pinned)),
		})
		observed := fixtureIndex(map[string]string{"/ui/actual.ts": "actual body", "/ui/helper.ts": "helper body"})
		directory := materializationScratch()

		_, err := MaterializeBuildContext(ctx, declaration, observed, directory, MaterializeBuildContextOptions{ContainerRoot: "/dk/context", WebpackSources: true})
		gomega.Expect(err).NotTo(gomega.HaveOccurred())

		var manifest struct {
			Components []struct {
				ID string `json:"id"`
			} `json:"components"`
			Files []struct {
				Path      string `json:"path"`
				Component string `json:"component"`
			} `json:"files"`
		}
		gomega.Expect(json.Unmarshal([]byte(materializedWebpackOriginals(directory)), &manifest)).To(gomega.Succeed())
		component := webpackComponentID(repo, pinned, "linux/amd64")
		gomega.Expect(manifest.Components).To(gomega.HaveLen(1))
		gomega.Expect(manifest.Components[0].ID).To(gomega.Equal(component))
		gomega.Expect(manifest.Files).To(gomega.HaveLen(2))
		for _, file := range manifest.Files {
			gomega.Expect(file.Component).To(gomega.Equal(component))
		}
	})

	ginkgo.It("names a verified Git original beside the pm imports, with the hooks its manifest defines", func(ctx ginkgo.SpecContext) {
		repo := originalRegistryHost(ctx) + "/test/original"
		pinned := pushOriginalImage(ctx, repo, "image", originalImageFixture("linux/amd64", map[string]string{"/ui/actual.ts": "actual body"}))
		declaration := fixtureDeclaration(repo, pinned, buildcontext.Import{Path: "/ui/actual.ts", Package: packageIndex(0), OriginalPath: "ui/actual.ts"})
		observed := fixtureIndex(map[string]string{"/ui/actual.ts": "actual body"})
		directory := materializationScratch()
		git := GitOriginal{
			Component: shared.BuildComponent{ID: "node:git", Name: "argo-ui", Version: "1.0.0", Source: shared.BuildSource{
				Kind: "node", Locator: "git+https://github.com/argoproj/argo-ui.git#" + strings.Repeat("a", 40), Checksum: "git-commit:sha1:" + strings.Repeat("a", 40),
			}},
			Files:     []GitOriginalFile{{Path: "/app/node_modules/argo-ui/index.js", SHA256: digest([]byte("installed body"))}},
			Lifecycle: []string{"prepare"},
		}

		_, err := MaterializeBuildContext(ctx, declaration, observed, directory, MaterializeBuildContextOptions{ContainerRoot: "/dk/context", WebpackSources: true, GitOriginals: []GitOriginal{git}})
		gomega.Expect(err).NotTo(gomega.HaveOccurred())

		component := webpackComponentID(repo, pinned, "linux/amd64")
		gomega.Expect(materializedWebpackOriginals(directory)).To(gomega.Equal(fmt.Sprintf(
			`{"version":1,"components":[{"id":"node:git","name":"argo-ui","version":"1.0.0","source":{"kind":"node","locator":%q,"checksum":%q}},{"id":%q,"name":"original","version":"1.0","source":{"kind":"pm","locator":%q,"checksum":%q}}],"files":[{"path":"/app/node_modules/argo-ui/index.js","sha256":%q,"component":"node:git"},{"path":"/ui/actual.ts","sha256":%q,"component":%q}],"lifecycle":[{"component":"node:git","hooks":["prepare"]}]}`,
			git.Component.Source.Locator, git.Component.Source.Checksum, component, repo, pinned,
			digest([]byte("installed body")), digest([]byte("actual body")), component)))
	})

	ginkgo.It("refuses a Git original the context would not carry a manifest for", func(ctx ginkgo.SpecContext) {
		repo := originalRegistryHost(ctx) + "/test/original"
		pinned := pushOriginalImage(ctx, repo, "image", originalImageFixture("linux/amd64", map[string]string{"/ui/actual.ts": "actual body"}))
		directory := materializationScratch()

		_, err := MaterializeBuildContext(ctx, fixtureDeclaration(repo, pinned), fixtureIndex(map[string]string{"/ui/actual.ts": "actual body"}), directory,
			MaterializeBuildContextOptions{ContainerRoot: "/dk/context", GitOriginals: []GitOriginal{{Component: shared.BuildComponent{ID: "node:git"}}}})
		gomega.Expect(err).To(gomega.MatchError(gomega.ContainSubstring("have no manifest to be named in")))
	})

	ginkgo.It("states the empty mapping of a context that imports nothing", func(ctx ginkgo.SpecContext) {
		repo := originalRegistryHost(ctx) + "/test/original"
		pinned := pushOriginalImage(ctx, repo, "image", originalImageFixture("linux/amd64", map[string]string{"/ui/actual.ts": "actual body"}))
		directory := materializationScratch()

		_, err := MaterializeBuildContext(ctx, fixtureDeclaration(repo, pinned), fixtureIndex(map[string]string{"/ui/actual.ts": "actual body"}), directory,
			MaterializeBuildContextOptions{ContainerRoot: "/dk/context", WebpackSources: true})
		gomega.Expect(err).NotTo(gomega.HaveOccurred())

		gomega.Expect(materializedWebpackOriginals(directory)).To(gomega.Equal(`{"version":1,"components":[],"files":[]}`))
	})

	ginkgo.It("leaves the context alone when the evidence is not asked for", func(ctx ginkgo.SpecContext) {
		repo := originalRegistryHost(ctx) + "/test/original"
		pinned := pushOriginalImage(ctx, repo, "image", originalImageFixture("linux/amd64", map[string]string{"/ui/actual.ts": "actual body"}))
		declaration := fixtureDeclaration(repo, pinned, buildcontext.Import{Path: "/ui/actual.ts", Package: packageIndex(0), OriginalPath: "ui/actual.ts"})
		observed := fixtureIndex(map[string]string{"/ui/actual.ts": "actual body"})
		withEvidence, plain := materializationScratch(), materializationScratch()

		_, err := MaterializeBuildContext(ctx, declaration, observed, withEvidence, MaterializeBuildContextOptions{ContainerRoot: "/dk/context", WebpackSources: true})
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		_, err = MaterializeBuildContext(ctx, declaration, observed, plain, MaterializeBuildContextOptions{ContainerRoot: "/dk/context"})
		gomega.Expect(err).NotTo(gomega.HaveOccurred())

		left, readErr := os.ReadDir(plain)
		gomega.Expect(readErr).NotTo(gomega.HaveOccurred())
		names := []string{}
		for _, entry := range left {
			names = append(names, entry.Name())
		}
		gomega.Expect(names).To(gomega.Equal([]string{materializedContextFile, materializedOriginalsDir}))
		// The context is the same artifact either way, scratch path included.
		beside, readErr := os.ReadFile(filepath.Join(withEvidence, materializedContextFile))
		gomega.Expect(readErr).NotTo(gomega.HaveOccurred())
		gomega.Expect(os.ReadFile(filepath.Join(plain, materializedContextFile))).To(gomega.Equal(beside))
	})

	ginkgo.It("writes nothing at all when an imported path holds other bytes than the original", func(ctx ginkgo.SpecContext) {
		repo := originalRegistryHost(ctx) + "/test/original"
		pinned := pushOriginalImage(ctx, repo, "image", originalImageFixture("linux/amd64", map[string]string{"/ui/actual.ts": "actual body"}))
		declaration := fixtureDeclaration(repo, pinned, buildcontext.Import{Path: "/ui/actual.ts", Package: packageIndex(0), OriginalPath: "ui/actual.ts"})
		directory := materializationScratch()

		_, err := MaterializeBuildContext(ctx, declaration, fixtureIndex(map[string]string{"/ui/actual.ts": "replaced body"}), directory,
			MaterializeBuildContextOptions{ContainerRoot: "/dk/context", WebpackSources: true})
		gomega.Expect(err).To(gomega.MatchError(gomega.ContainSubstring("the original no longer holds the expected bytes")))

		left, readErr := os.ReadDir(directory)
		gomega.Expect(readErr).NotTo(gomega.HaveOccurred())
		gomega.Expect(left).To(gomega.BeEmpty())
	})

	ginkgo.It("writes no evidence for an import mapping the declaration cannot prove", func(ctx ginkgo.SpecContext) {
		repo := originalRegistryHost(ctx) + "/test/original"
		pinned := pushOriginalImage(ctx, repo, "image", originalImageFixture("linux/amd64", map[string]string{"/ui/actual.ts": "actual body"}))
		declaration := fixtureDeclaration(repo, pinned, buildcontext.Import{Path: "/ui/actual.ts", Package: packageIndex(0), OriginalPath: "../etc/shadow"})
		directory := materializationScratch()

		_, err := MaterializeBuildContext(ctx, declaration, fixtureIndex(map[string]string{"/ui/actual.ts": "actual body"}), directory,
			MaterializeBuildContextOptions{ContainerRoot: "/dk/context", WebpackSources: true})
		gomega.Expect(err).To(gomega.MatchError(gomega.ContainSubstring(`invalid original package path "../etc/shadow"`)))

		left, readErr := os.ReadDir(directory)
		gomega.Expect(readErr).NotTo(gomega.HaveOccurred())
		gomega.Expect(left).To(gomega.BeEmpty())
	})

	ginkgo.It("writes the same bytes through a second scratch directory", func(ctx ginkgo.SpecContext) {
		repo := originalRegistryHost(ctx) + "/test/original"
		pinned := pushOriginalImage(ctx, repo, "image", originalImageFixture("linux/amd64", map[string]string{
			"/ui/actual.ts": "actual body",
			"/ui/helper.ts": "helper body",
		}))
		declaration := fixtureDeclaration(repo, pinned,
			buildcontext.Import{Path: "/ui/helper.ts", Package: packageIndex(0), OriginalPath: "ui/helper.ts"},
			buildcontext.Import{Path: "/ui/actual.ts", Package: packageIndex(0), OriginalPath: "ui/actual.ts"},
		)
		observed := fixtureIndex(map[string]string{"/ui/actual.ts": "actual body", "/ui/helper.ts": "helper body"})
		first, second := materializationScratch(), materializationScratch()

		_, err := MaterializeBuildContext(ctx, declaration, observed, first, MaterializeBuildContextOptions{ContainerRoot: "/dk/context", WebpackSources: true})
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		_, err = MaterializeBuildContext(ctx, declaration, observed, second, MaterializeBuildContextOptions{ContainerRoot: "/dk/context", WebpackSources: true})
		gomega.Expect(err).NotTo(gomega.HaveOccurred())

		gomega.Expect(materializedWebpackOriginals(second)).To(gomega.Equal(materializedWebpackOriginals(first)))
	})
})
