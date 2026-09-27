package e2e_build_test

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	sbomtest "github.com/werf/werf/v3/test/pkg/sbom"
	"github.com/werf/werf/v3/test/pkg/werf"
)

var _ = Describe("SBOM python-pip packages", Label("e2e", "sbom", "pip", "simple"), func() {
	It("catalogs requirements.txt dependencies into the BOM", func(ctx SpecContext) {
		setupSbomBuildEnv()

		repoDirname := "repo_sbom_python_pip_simple"
		SuiteData.InitTestRepo(ctx, repoDirname, "inject/pip_simple")
		testRepoPath := SuiteData.GetTestRepoPath(repoDirname)

		werfProject := werf.NewProject(SuiteData.WerfBinPath, testRepoPath)
		werfProject.Build(ctx, &werf.BuildOptions{CommonOptions: werf.CommonOptions{}})

		sbomOut := werfProject.SbomGet(ctx, &werf.SbomGetOptions{
			CommonOptions: werf.CommonOptions{
				ExtraArgs: []string{"app"},
			},
		})

		bom := sbomtest.MustParseSBOMOutput(sbomOut)
		requests := sbomtest.FindComponent(bom, "requests", "2.32.3")
		Expect(requests).NotTo(BeNil(),
			"expected requests@2.32.3 (from requirements.txt) not found in BOM")
	})

	It("installs with pip even when the project ships a module named pip", func(ctx SpecContext) {
		setupSbomBuildEnv()

		repoDirname := "repo_sbom_python_pip_module_shadow"
		SuiteData.InitTestRepo(ctx, repoDirname, "inject/pip_module_shadow")
		testRepoPath := SuiteData.GetTestRepoPath(repoDirname)

		werfProject := werf.NewProject(SuiteData.WerfBinPath, testRepoPath)
		werfProject.Build(ctx, &werf.BuildOptions{CommonOptions: werf.CommonOptions{}})

		sbomOut := werfProject.SbomGet(ctx, &werf.SbomGetOptions{
			CommonOptions: werf.CommonOptions{
				ExtraArgs: []string{"app"},
			},
		})

		bom := sbomtest.MustParseSBOMOutput(sbomOut)
		requests := sbomtest.FindComponent(bom, "requests", "2.32.3")
		Expect(requests).NotTo(BeNil(),
			"expected requests@2.32.3 in BOM: the project pip.py shadowed the installer and the packages stage reported success without installing anything")
	})
})
