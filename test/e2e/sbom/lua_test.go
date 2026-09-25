package e2e_build_test

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	sbomtest "github.com/werf/werf/v3/test/pkg/sbom"
	"github.com/werf/werf/v3/test/pkg/werf"
)

var _ = Describe("SBOM lua-rock packages", Label("e2e", "sbom", "lua", "simple"), func() {
	It("catalogs rockspec dependencies into the BOM", func(ctx SpecContext) {
		setupSbomBuildEnv()

		repoDirname := "repo_sbom_lua_rock_simple"
		SuiteData.InitTestRepo(ctx, repoDirname, "inject/lua_simple")
		testRepoPath := SuiteData.GetTestRepoPath(repoDirname)

		builderEnv := buildTrustedBuilderBase(ctx, testRepoPath, "sbom-lua-rock-builder")

		werfProject := werf.NewProject(SuiteData.WerfBinPath, testRepoPath)
		werfProject.Build(ctx, &werf.BuildOptions{CommonOptions: werf.CommonOptions{Envs: builderEnv}})

		sbomOut := werfProject.SbomGet(ctx, &werf.SbomGetOptions{
			CommonOptions: werf.CommonOptions{
				ExtraArgs: []string{"app"},
				Envs:      builderEnv,
			},
		})

		bom := sbomtest.MustParseSBOMOutput(sbomOut)
		app := sbomtest.FindComponent(bom, "werf-sbom-lua-app", "0.1-1")
		Expect(app).NotTo(BeNil(),
			"expected werf-sbom-lua-app@0.1-1 (from rockspec) not found in BOM")
	})

	It("build fails when the declared rockspec is missing from the build context", func(ctx SpecContext) {
		setupSbomBuildEnv()

		repoDirname := "repo_sbom_lua_rock_missing"
		SuiteData.InitTestRepo(ctx, repoDirname, "negative/lua_missing_rockspec")
		testRepoPath := SuiteData.GetTestRepoPath(repoDirname)

		builderEnv := buildTrustedBuilderBase(ctx, testRepoPath, "sbom-lua-rock-missing-builder")

		werfProject := werf.NewProject(SuiteData.WerfBinPath, testRepoPath)
		out := werfProject.Build(ctx, &werf.BuildOptions{
			CommonOptions: werf.CommonOptions{
				ShouldFail: true,
				Envs:       builderEnv,
			},
		})
		Expect(out).To(SatisfyAny(
			ContainSubstring("rockspec"),
			ContainSubstring("luarocks"),
		), "expected luarocks failure on missing rockspec; got:\n%s", out)
	})
})
