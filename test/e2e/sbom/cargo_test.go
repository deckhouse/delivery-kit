package e2e_build_test

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	sbomtest "github.com/werf/werf/v3/test/pkg/sbom"
	"github.com/werf/werf/v3/test/pkg/werf"
)

var _ = Describe("SBOM rust-cargo packages", Label("e2e", "sbom", "cargo", "simple"), func() {
	It("catalogs Cargo.lock dependencies into the BOM", func(ctx SpecContext) {
		setupSbomBuildEnv()

		repoDirname := "repo_sbom_rust_cargo_simple"
		SuiteData.InitTestRepo(ctx, repoDirname, "inject/cargo_simple")
		testRepoPath := SuiteData.GetTestRepoPath(repoDirname)

		werfProject := werf.NewProject(SuiteData.WerfBinPath, testRepoPath)
		werfProject.Build(ctx, &werf.BuildOptions{CommonOptions: werf.CommonOptions{}})

		sbomOut := werfProject.SbomGet(ctx, &werf.SbomGetOptions{
			CommonOptions: werf.CommonOptions{
				ExtraArgs: []string{"app"},
			},
		})

		bom := sbomtest.MustParseSBOMOutput(sbomOut)
		anyhow := sbomtest.FindComponent(bom, "anyhow", "1.0.86")
		Expect(anyhow).NotTo(BeNil(),
			"expected anyhow@1.0.86 (from Cargo.lock) not found in BOM")

		sbomtest.AssertHasLicense(bom, "rust", "1.96.0", "Apache-2.0 OR MIT")
	})
})
