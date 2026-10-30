package nativegate

import (
	"strings"

	shared "fox.flant.com/deckhouse/container-base/pm.git/sbom"
	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"
)

const prebuiltInstalledPath = "/app/node_modules/redoc/bundles/redoc.standalone.js"

var prebuiltBundleDigest = "sha256:" + strings.Repeat("a", 64)

func prebuiltFixtureOriginals(digest string) webpackOriginals {
	return webpackOriginals{
		Version: 1,
		Files: []webpackOriginalFile{
			{Path: "/app/src/main.ts", SHA256: "sha256:" + strings.Repeat("d", 64), Component: "npm:app@1.0.0"},
			{Path: prebuiltInstalledPath, SHA256: digest, Component: "node:redoc@2.4.0"},
		},
	}
}

func prebuiltFixtureAsset(overrides func(*PrebuiltAsset)) PrebuiltAsset {
	asset := PrebuiltAsset{
		InstalledPath: prebuiltInstalledPath,
		SHA256:        prebuiltBundleDigest,
		Components: []shared.BuildComponent{{
			ID: "node:redoc@2.4.0", Name: "redoc", Version: "2.4.0",
			Source: shared.BuildSource{Kind: "node", Locator: "https://registry.yarnpkg.com/redoc/-/redoc-2.4.0.tgz", Checksum: "sha512-" + strings.Repeat("c", 86) + "=="},
		}},
		Inputs: []PrebuiltInput{{Path: "src/index.tsx", SHA256: "sha256:" + strings.Repeat("b", 64), Components: []string{"node:redoc@2.4.0"}}},
	}
	if overrides != nil {
		overrides(&asset)
	}

	return asset
}

var _ = ginkgo.Describe("Writing the delivered compositions of a build context", func() {
	ginkgo.It("states a composition under the digest the installed file was proven against", func() {
		body, err := webpackPrebuiltManifest(prebuiltFixtureOriginals(prebuiltBundleDigest), []PrebuiltAsset{prebuiltFixtureAsset(nil)})
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(string(body)).To(gomega.Equal(
			`{"version":1,"entries":[{"sha256":"` + prebuiltBundleDigest + `",` +
				`"components":[{"id":"node:redoc@2.4.0","name":"redoc","version":"2.4.0","source":{"kind":"node","locator":"https://registry.yarnpkg.com/redoc/-/redoc-2.4.0.tgz","checksum":"sha512-` + strings.Repeat("c", 86) + `=="}}],` +
				`"inputs":[{"path":"src/index.tsx","sha256":"sha256:` + strings.Repeat("b", 64) + `","components":["node:redoc@2.4.0"]}]}]}`,
		))
	})

	// The whole of the join: the npm distribution this build installs, verified
	// against its own original, must serve the very bytes the rebuild emitted.
	ginkgo.It("refuses a delivery for bytes the installed file does not serve", func() {
		_, err := webpackPrebuiltManifest(prebuiltFixtureOriginals("sha256:"+strings.Repeat("e", 64)), []PrebuiltAsset{prebuiltFixtureAsset(nil)})
		gomega.Expect(err).To(gomega.MatchError(gomega.ContainSubstring("hash-mismatch: " + prebuiltInstalledPath + " serves sha256:" + strings.Repeat("e", 64))))
	})

	// A dependency the project's own package manager installed is no import of
	// this context and has no digest here. The equality is then the collector's
	// to establish, under the digest of bytes it binds to that package's own
	// verified original, so the entry is written and the bytes still decide.
	ginkgo.It("states a composition for a file the project's package manager installed", func() {
		body, err := webpackPrebuiltManifest(webpackOriginals{Version: 1}, []PrebuiltAsset{prebuiltFixtureAsset(nil)})
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(string(body)).To(gomega.ContainSubstring(`"sha256":"` + prebuiltBundleDigest + `"`))
	})

	ginkgo.DescribeTable("refuses a composition it cannot hold to the rules of this context", func(overrides func(*PrebuiltAsset), expected string) {
		asset := prebuiltFixtureAsset(overrides)
		_, err := webpackPrebuiltManifest(prebuiltFixtureOriginals(asset.SHA256), []PrebuiltAsset{asset})
		gomega.Expect(err).To(gomega.MatchError(gomega.ContainSubstring(expected)))
	},
		ginkgo.Entry("no digest at all", func(asset *PrebuiltAsset) { asset.SHA256 = "nope" }, "is delivered under no sha256 digest"),
		ginkgo.Entry("no components", func(asset *PrebuiltAsset) { asset.Components = nil }, "is delivered with no components"),
		// A composition of components alone states what the file is said to
		// contain without stating one byte it was built from.
		ginkgo.Entry("no inputs", func(asset *PrebuiltAsset) { asset.Inputs = nil }, "is delivered with no inputs"),
		ginkgo.Entry("a component no input is claimed by", func(asset *PrebuiltAsset) {
			asset.Components = append(asset.Components, shared.BuildComponent{
				ID: "node:unclaimed@1.0.0", Name: "unclaimed", Version: "1.0.0",
				Source: shared.BuildSource{Kind: "node", Locator: "https://registry.yarnpkg.com/unclaimed/-/unclaimed-1.0.0.tgz", Checksum: "sha512-" + strings.Repeat("d", 86) + "=="},
			})
		}, "delivered with component node:unclaimed@1.0.0 no input is claimed by"),
		ginkgo.Entry("a repeated component", func(asset *PrebuiltAsset) {
			asset.Components = append(asset.Components, asset.Components[0])
		}, "unnamed or repeated component"),
		ginkgo.Entry("a component with no version", func(asset *PrebuiltAsset) { asset.Components[0].Version = "" }, "carrying no exact name and version"),
		// A published archive, or a Git commit named by the locator it was fetched
		// through: the rebuild could have written neither unless this machinery had
		// resolved it first.
		ginkgo.Entry("a component of an unverifiable kind", func(asset *PrebuiltAsset) { asset.Components[0].Source.Kind = "guess" }, "of an unverifiable kind"),
		ginkgo.Entry("a component pinning no archive", func(asset *PrebuiltAsset) { asset.Components[0].Source.Checksum = "" }, "pinning no archive"),
		// A prepared source image is stated by its own digest, which is what the
		// shared schema requires of a pm component.
		ginkgo.Entry("a prepared source pinning no image digest", func(asset *PrebuiltAsset) {
			asset.Components[0].Source.Kind = "pm"
		}, "pinning no image digest"),
		ginkgo.Entry("a Git component whose checksum names another commit", func(asset *PrebuiltAsset) {
			asset.Components[0].Source = shared.BuildSource{
				Kind: "node", Locator: "git+https://example.test/redoc.git#" + strings.Repeat("1", 40), Checksum: "git-commit:sha1:" + strings.Repeat("2", 40),
			}
		}, "pinning no Git commit"),
		ginkgo.Entry("a Git component pinned to no commit at all", func(asset *PrebuiltAsset) {
			asset.Components[0].Source = shared.BuildSource{Kind: "node", Locator: "git+https://example.test/redoc.git#main", Checksum: "sha512-x"}
		}, "pinning no Git commit"),
		ginkgo.Entry("an input of no component", func(asset *PrebuiltAsset) { asset.Inputs[0].Components = nil }, "claimed by no component"),
		ginkgo.Entry("an input of an unstated component", func(asset *PrebuiltAsset) {
			asset.Inputs[0].Components = []string{"npm:ghost@1.0.0"}
		}, "claimed by the unknown component npm:ghost@1.0.0"),
		ginkgo.Entry("an undigested input", func(asset *PrebuiltAsset) { asset.Inputs[0].SHA256 = "nope" }, "unnamed or undigested input"),
	)

	// The ordinary case: a dependency of the rebuild installed from the registry
	// its lockfile names, stated by that entry's integrity.
	ginkgo.It("accepts a dependency installed from a published archive", func() {
		asset := prebuiltFixtureAsset(nil)
		_, err := webpackPrebuiltManifest(prebuiltFixtureOriginals(asset.SHA256), []PrebuiltAsset{asset})
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
	})

	ginkgo.It("accepts a prepared source stated by its image digest", func() {
		asset := prebuiltFixtureAsset(func(asset *PrebuiltAsset) {
			asset.Components[0].Source = shared.BuildSource{Kind: "pm", Locator: "example.test/source", Checksum: "sha256:" + strings.Repeat("9", 64)}
		})
		_, err := webpackPrebuiltManifest(prebuiltFixtureOriginals(asset.SHA256), []PrebuiltAsset{asset})
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
	})

	ginkgo.It("accepts a component pinned to the Git commit of its own locator", func() {
		asset := prebuiltFixtureAsset(func(asset *PrebuiltAsset) {
			asset.Components[0].Source = shared.BuildSource{
				Kind: "node", Locator: "git+https://example.test/redoc.git#" + strings.Repeat("1", 40), Checksum: "git-commit:sha1:" + strings.Repeat("1", 40),
			}
		})
		_, err := webpackPrebuiltManifest(prebuiltFixtureOriginals(asset.SHA256), []PrebuiltAsset{asset})
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
	})

	// One composition per bytes: the same delivery twice is one entry, a second
	// account of the same bytes is a contradiction.
	ginkgo.It("states one entry for a delivery that repeats itself", func() {
		asset := prebuiltFixtureAsset(nil)
		body, err := webpackPrebuiltManifest(prebuiltFixtureOriginals(asset.SHA256), []PrebuiltAsset{asset, asset})
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(strings.Count(string(body), `"sha256":"`+prebuiltBundleDigest)).To(gomega.Equal(1))
	})

	ginkgo.It("refuses two compositions for one digest", func() {
		first := prebuiltFixtureAsset(nil)
		second := prebuiltFixtureAsset(func(asset *PrebuiltAsset) { asset.Inputs[0].Path = "src/other.tsx" })
		_, err := webpackPrebuiltManifest(prebuiltFixtureOriginals(first.SHA256), []PrebuiltAsset{first, second})
		gomega.Expect(err).To(gomega.MatchError(gomega.ContainSubstring("is delivered with a second composition")))
	})

	// The order two accounts of the same bytes were written in is not a
	// difference between them.
	ginkgo.It("states one entry for the same composition written in another order", func() {
		extra := shared.BuildComponent{
			ID: "node:other@1.0.0", Name: "other", Version: "1.0.0",
			Source: shared.BuildSource{Kind: "node", Locator: "https://registry.yarnpkg.com/other/-/other-1.0.0.tgz", Checksum: "sha512-" + strings.Repeat("e", 86) + "=="},
		}
		first := prebuiltFixtureAsset(func(asset *PrebuiltAsset) {
			asset.Components = append(asset.Components, extra)
			asset.Inputs = append(asset.Inputs, PrebuiltInput{Path: "src/a.ts", SHA256: "sha256:" + strings.Repeat("f", 64), Components: []string{"node:redoc@2.4.0", extra.ID}})
		})
		second := prebuiltFixtureAsset(func(asset *PrebuiltAsset) {
			asset.Components = []shared.BuildComponent{extra, asset.Components[0]}
			asset.Inputs = []PrebuiltInput{
				{Path: "src/a.ts", SHA256: "sha256:" + strings.Repeat("f", 64), Components: []string{extra.ID, "node:redoc@2.4.0"}},
				asset.Inputs[0],
			}
		})
		body, err := webpackPrebuiltManifest(prebuiltFixtureOriginals(first.SHA256), []PrebuiltAsset{first, second})
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(strings.Count(string(body), `"sha256":"`+prebuiltBundleDigest)).To(gomega.Equal(1))
	})
})
