package e2e_build_test

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	sbomtest "github.com/werf/werf/v3/test/pkg/sbom"
	"github.com/werf/werf/v3/test/pkg/werf"
)

var _ = Describe("SBOM javascript-npm packages", Label("e2e", "sbom", "npm", "simple"), func() {
	It("catalogs package-lock.json dependencies into the BOM", func(ctx SpecContext) {
		setupSbomBuildEnv()

		repoDirname := "repo_sbom_npm_simple"
		SuiteData.InitTestRepo(ctx, repoDirname, "inject/npm_simple")
		testRepoPath := SuiteData.GetTestRepoPath(repoDirname)

		werfProject := werf.NewProject(SuiteData.WerfBinPath, testRepoPath)
		werfProject.Build(ctx, &werf.BuildOptions{CommonOptions: werf.CommonOptions{}})

		sbomOut := werfProject.SbomGet(ctx, &werf.SbomGetOptions{
			CommonOptions: werf.CommonOptions{
				ExtraArgs: []string{"app"},
			},
		})

		bom := sbomtest.MustParseSBOMOutput(sbomOut)
		lodash := sbomtest.FindComponent(bom, "lodash", "4.17.21")
		Expect(lodash).NotTo(BeNil(),
			"expected lodash@4.17.21 (from package-lock.json) not found in BOM")
	})
})
