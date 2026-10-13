package e2e_build_test

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	sbomtest "github.com/werf/werf/v3/test/pkg/sbom"
	"github.com/werf/werf/v3/test/pkg/werf"
)

var _ = Describe("SBOM javascript-yarn packages with Yarn Berry", Label("e2e", "sbom", "yarn", "simple"), func() {
	It("installs dependencies with the same command Yarn Classic takes", func(ctx SpecContext) {
		setupSbomBuildEnv()

		repoDirname := "repo_sbom_yarn_berry"
		SuiteData.InitTestRepo(ctx, repoDirname, "inject/yarn_berry")
		testRepoPath := SuiteData.GetTestRepoPath(repoDirname)

		werfProject := werf.NewProject(SuiteData.WerfBinPath, testRepoPath)
		werfProject.Build(ctx, &werf.BuildOptions{CommonOptions: werf.CommonOptions{}})

		sbomOut := werfProject.SbomGet(ctx, &werf.SbomGetOptions{
			CommonOptions: werf.CommonOptions{
				ExtraArgs: []string{"app"},
			},
		})

		bom := sbomtest.MustParseSBOMOutput(sbomOut)
		Expect(sbomtest.FindComponent(bom, "lodash", "4.17.21")).NotTo(BeNil(),
			"expected lodash@4.17.21 (from the Berry yarn.lock) not found in BOM")
		Expect(sbomtest.FindComponent(bom, "@yarnpkg/cli-dist", "4.18.1")).NotTo(BeNil(),
			"expected the bootstrapped @yarnpkg/cli-dist@4.18.1 not found in BOM")

		// Berry links through PnP by default, which leaves no node_modules for syft to read
		// licenses from; the fixture selects the node-modules linker in .yarnrc.yml.
		sbomtest.AssertHasLicense(bom, "lodash", "4.17.21", "MIT")
	})
})
