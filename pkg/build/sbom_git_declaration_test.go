package build

import (
	"encoding/json"
	"strings"

	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"
)

var _ = ginkgo.Describe("producer git source declarations", func() {
	const commit = "a1c32a45e83fdda4baafc7ca3105c3ead383f8ba"
	binding := `{"to":"/src/originals/argo-ui","locator":"git+https://github.com/argoproj/argo-ui.git#` + commit + `","installedPath":"/app/node_modules/argo-ui","packageName":"argo-ui","packageVersion":"1.0.0"}`
	declaration := func(sources string) []byte {
		return []byte(`{"version":1,"stages":{"install":{"subject":0,` + webpackStageSettings + `,"packages":[{"sourceImage":"source","packageName":"app-source","packageVersion":"1","packageType":"source","sourcePlatform":"linux/amd64"}],"gitSources":` + sources + `}}}`)
	}

	ginkgo.It("binds a lock locator to the mapping that fetches it", func() {
		parsed, err := parseSBOMBuildContextDeclaration(declaration("[" + binding + "]"))
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(parsed.Stages["install"].GitSources).To(gomega.Equal([]sbomBuildContextGitSource{{
			To:             "/src/originals/argo-ui",
			Locator:        "git+https://github.com/argoproj/argo-ui.git#" + commit,
			InstalledPath:  "/app/node_modules/argo-ui",
			PackageName:    "argo-ui",
			PackageVersion: "1.0.0",
		}}))
	})

	ginkgo.DescribeTable("refuses a binding that pins no distribution", func(sources string) {
		_, err := parseSBOMBuildContextDeclaration(declaration(sources))
		gomega.Expect(err).To(gomega.HaveOccurred())
	},
		ginkgo.Entry("null", "null"),
		ginkgo.Entry("not an array", binding),
		ginkgo.Entry("missing members", `[{}]`),
		ginkgo.Entry("unknown member", "["+strings.Replace(binding, `"packageName"`, `"extra":true,"packageName"`, 1)+"]"),
		ginkgo.Entry("duplicate member", "["+strings.Replace(binding, `"packageName"`, `"packageName":"other","packageName"`, 1)+"]"),
		ginkgo.Entry("relative mapping", "["+strings.Replace(binding, `"/src/originals/argo-ui"`, `"src/originals/argo-ui"`, 1)+"]"),
		ginkgo.Entry("unclean installed path", "["+strings.Replace(binding, `"/app/node_modules/argo-ui"`, `"/app/node_modules/../argo-ui"`, 1)+"]"),
		ginkgo.Entry("installed outside node_modules", "["+strings.Replace(binding, `"/app/node_modules/argo-ui"`, `"/app/vendor/argo-ui"`, 1)+"]"),
		ginkgo.Entry("installed as another package", "["+strings.Replace(binding, `"/app/node_modules/argo-ui"`, `"/app/node_modules/argo-ui-fork"`, 1)+"]"),
		ginkgo.Entry("locator without a commit", "["+strings.Replace(binding, "#"+commit, "", 1)+"]"),
		ginkgo.Entry("locator pinned to a branch", "["+strings.Replace(binding, commit, "master", 1)+"]"),
		ginkgo.Entry("locator pinned to a short commit", "["+strings.Replace(binding, commit, commit[:8], 1)+"]"),
		ginkgo.Entry("locator pinned to an upper-case commit", "["+strings.Replace(binding, commit, strings.ToUpper(commit), 1)+"]"),
		ginkgo.Entry("registry locator", "["+strings.Replace(binding, "git+https://", "https://", 1)+"]"),
		ginkgo.Entry("locator with whitespace", "["+strings.Replace(binding, "git+https://", "git+https:// ", 1)+"]"),
		ginkgo.Entry("same mapping twice", "["+binding+","+strings.Replace(binding, `"/app/node_modules/argo-ui"`, `"/app/ui/node_modules/argo-ui"`, 1)+"]"),
		ginkgo.Entry("same install twice", "["+binding+","+strings.Replace(binding, `"/src/originals/argo-ui"`, `"/src/originals/argo-ui-again"`, 1)+"]"),
	)

	ginkgo.It("refuses a binding the stage carries no originals manifest for", func() {
		plain := strings.Replace(string(declaration("["+binding+"]")), webpackStageSettings+",", "", 1)
		_, err := parseSBOMBuildContextDeclaration([]byte(plain))
		gomega.Expect(err).To(gomega.MatchError(gomega.ContainSubstring("gitSources require webpackSources")))
	})

	ginkgo.It("leaves a stage without git bindings alone", func() {
		parsed, err := parseSBOMBuildContextDeclaration(declaration("[]"))
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(parsed.Stages["install"].GitSources).To(gomega.BeEmpty())
	})

	// The producer context takes the stage checksum from this very encoding, so a
	// binding that is not in it would not rebuild the stage it changes.
	ginkgo.It("keeps the bindings in the encoded stage intent", func() {
		parsed, err := parseSBOMBuildContextDeclaration(declaration("[" + binding + "]"))
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(json.Marshal(parsed.Stages["install"])).To(gomega.ContainSubstring(`"gitSources":[{"to":"/src/originals/argo-ui","locator":"git+https://github.com/argoproj/argo-ui.git#` + commit + `"`))

		bare, err := parseSBOMBuildContextDeclaration(declaration("[]"))
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(json.Marshal(bare.Stages["install"])).NotTo(gomega.ContainSubstring("gitSources"))
	})
})

var _ = ginkgo.Describe("producer git source declarations of the project itself", func() {
	project := `{"to":"/app","kind":"project","installedPath":"/app"}`
	declaration := func(sources string) []byte {
		return []byte(`{"version":1,"stages":{"install":{"subject":0,` + webpackStageSettings + `,"packages":[{"sourceImage":"source","packageName":"app-source","packageVersion":"1","packageType":"source","sourcePlatform":"linux/amd64"}],"gitSources":` + sources + `}}}`)
	}

	// The project is not a dependency of itself: the mapping that adds it and the
	// place it is added at are the whole of the binding.
	ginkgo.It("binds the project root to the mapping that adds it", func() {
		parsed, err := parseSBOMBuildContextDeclaration(declaration("[" + project + "]"))
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(parsed.Stages["install"].GitSources).To(gomega.Equal([]sbomBuildContextGitSource{{
			To:            "/app",
			Kind:          "project",
			InstalledPath: "/app",
		}}))
	})

	ginkgo.DescribeTable("refuses a project binding that names itself by a lock entry", func(member, value string) {
		_, err := parseSBOMBuildContextDeclaration(declaration("[" + strings.Replace(project, `"installedPath"`, `"`+member+`":`+value+`,"installedPath"`, 1) + "]"))
		gomega.Expect(err).To(gomega.MatchError(gomega.ContainSubstring("a project names itself by its commit, not by " + member)))
	},
		ginkgo.Entry("locator", "locator", `"git+https://github.com/Redocly/redoc.git#124309592670979d1a647718e5ad94b9b9e56e48"`),
		ginkgo.Entry("packageName", "packageName", `"redoc"`),
		ginkgo.Entry("packageVersion", "packageVersion", `"2.4.0"`),
	)

	// The project is its own sources: the mapping that adds them is where they are,
	// unlike a dependency, which its mapping only delivers and the package manager
	// installs elsewhere.
	ginkgo.It("refuses a project installed anywhere but where its mapping adds it", func() {
		_, err := parseSBOMBuildContextDeclaration(declaration(`[{"to":"/app","kind":"project","installedPath":"/app/src"}]`))
		gomega.Expect(err).To(gomega.MatchError(gomega.ContainSubstring("a project is installed where its mapping adds it, not at /app/src")))
	})

	ginkgo.It("refuses a kind that is no kind of Git source", func() {
		_, err := parseSBOMBuildContextDeclaration(declaration(`[{"to":"/app","kind":"primary","installedPath":"/app"}]`))
		gomega.Expect(err).To(gomega.MatchError(gomega.ContainSubstring(`kind "primary" is not a kind of Git source`)))
	})

	// A dependency keeps every one of its own requirements, named kind or not.
	ginkgo.It("still requires a dependency to pin a distribution", func() {
		for _, kind := range []string{"", `"kind":"dependency",`} {
			_, err := parseSBOMBuildContextDeclaration(declaration(`[{"to":"/src/x",` + kind + `"installedPath":"/app/node_modules/x"}]`))
			gomega.Expect(err).To(gomega.MatchError(gomega.ContainSubstring("locator is required")))
		}
	})
})

var _ = ginkgo.Describe("producer git mirror declarations", func() {
	const mirror = `{"host":"fox.flant.com","pathPrefix":"deckhouse/3p","upstreamHost":"github.com"}`
	declaration := func(mirrors string) []byte {
		return []byte(`{"version":1,"gitMirrors":` + mirrors + `,"stages":{"install":{"subject":0,"packages":[{"sourceImage":"source","packageName":"app-source","packageVersion":"1","packageType":"source","sourcePlatform":"linux/amd64"}]}}}`)
	}

	ginkgo.It("lists the mirror a Git-locked source may be fetched from", func() {
		parsed, err := parseSBOMBuildContextDeclaration(declaration("[" + mirror + "]"))
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(parsed.GitMirrors).To(gomega.Equal([]sbomBuildContextGitMirror{{
			Host: "fox.flant.com", PathPrefix: "deckhouse/3p", UpstreamHost: "github.com",
		}}))
	})

	ginkgo.It("leaves a declaration without mirrors alone", func() {
		parsed, err := parseSBOMBuildContextDeclaration(declaration("[]"))
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(parsed.GitMirrors).To(gomega.BeEmpty())
	})

	ginkgo.DescribeTable("refuses an entry that states no mirror", func(mirrors, message string) {
		_, err := parseSBOMBuildContextDeclaration(declaration(mirrors))
		gomega.Expect(err).To(gomega.MatchError(gomega.ContainSubstring(message)))
	},
		ginkgo.Entry("missing members", `[{}]`, `gitMirror 0: host "" is not a bare host`),
		ginkgo.Entry("unknown member", "["+strings.Replace(mirror, `"pathPrefix"`, `"token":"secret","pathPrefix"`, 1)+"]", "unknown field"),
		ginkgo.Entry("credentials in the host", "["+strings.Replace(mirror, `"fox.flant.com"`, `"gitlab-ci-token:secret@fox.flant.com"`, 1)+"]", "is not a bare host"),
		ginkgo.Entry("a transport in the host", "["+strings.Replace(mirror, `"fox.flant.com"`, `"https://fox.flant.com"`, 1)+"]", "is not a bare host"),
		ginkgo.Entry("an absolute prefix", "["+strings.Replace(mirror, `"deckhouse/3p"`, `"/deckhouse/3p"`, 1)+"]", "is not a path of the mirror host"),
		ginkgo.Entry("a relative segment", "["+strings.Replace(mirror, `"deckhouse/3p"`, `"deckhouse/../3p"`, 1)+"]", "is not a path of the mirror host"),
		ginkgo.Entry("the same mirror twice", "["+mirror+","+strings.Replace(mirror, `"github.com"`, `"gitlab.example"`, 1)+"]", "is listed more than once"),
	)

	// The declaration is the image's own label, and the stage is rebuilt from the
	// encoding of it: a mirror added to the allowlist changes what is accepted.
	ginkgo.It("keeps the mirrors in the encoded declaration", func() {
		parsed, err := parseSBOMBuildContextDeclaration(declaration("[" + mirror + "]"))
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(json.Marshal(parsed)).To(gomega.ContainSubstring(`"gitMirrors":[` + mirror + `]`))
	})
})
