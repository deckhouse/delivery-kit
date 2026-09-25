package e2e_build_test

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	sbomtest "github.com/werf/werf/v3/test/pkg/sbom"
	"github.com/werf/werf/v3/test/pkg/utils"
	"github.com/werf/werf/v3/test/pkg/werf"
)

var _ = Describe("SBOM go-mod packages", Label("e2e", "sbom", "gomod", "simple"), func() {
	It("resolves local 'replace' directive to a version in the BOM", func(ctx SpecContext) {
		setupSbomBuildEnv()

		repoDirname := "repo_sbom_inject_gomod_replace"
		SuiteData.InitTestRepo(ctx, repoDirname, "inject/gomod_replace")
		testRepoPath := SuiteData.GetTestRepoPath(repoDirname)

		utils.RunSucceedCommand(ctx, testRepoPath, "git", "tag", "v1.0.0")

		builderEnv := buildTrustedBuilderBase(ctx, testRepoPath, "sbom-inject-gomod-replace-builder")

		werfProject := werf.NewProject(SuiteData.WerfBinPath, testRepoPath)
		werfProject.Build(ctx, &werf.BuildOptions{CommonOptions: werf.CommonOptions{Envs: builderEnv}})

		sbomOut := werfProject.SbomGet(ctx, &werf.SbomGetOptions{
			CommonOptions: werf.CommonOptions{
				ExtraArgs: []string{"app"},
				Envs:      builderEnv,
			},
		})

		bom := sbomtest.MustParseSBOMOutput(sbomOut)
		mylib := sbomtest.FindComponent(bom, "example.com/mylib", "v1.0.0")
		Expect(mylib).NotTo(BeNil(),
			"expected example.com/mylib@v1.0.0 (resolved from local replace via git tag) not found in BOM")
	})
})
