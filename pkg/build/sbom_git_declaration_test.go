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
		return []byte(`{"version":1,"stages":{"install":{"subject":0,"webpackSources":true,"packages":[{"sourceImage":"source","packageName":"app-source","packageVersion":"1","packageType":"source","sourcePlatform":"linux/amd64"}],"gitSources":` + sources + `}}}`)
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
		plain := strings.Replace(string(declaration("["+binding+"]")), `"webpackSources":true,`, "", 1)
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
