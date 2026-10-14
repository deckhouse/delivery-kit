package e2e_build_test

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	sbomtest "github.com/werf/werf/v3/test/pkg/sbom"
	"github.com/werf/werf/v3/test/pkg/utils"
	"github.com/werf/werf/v3/test/pkg/werf"
)

var _ = Describe("SBOM python-poetry packages", Label("e2e", "sbom", "poetry", "simple"), func() {
	It("catalogs poetry.lock dependencies into the BOM", func(ctx SpecContext) {
		setupSbomBuildEnv()

		repoDirname := "repo_sbom_python_poetry_simple"
		SuiteData.InitTestRepo(ctx, repoDirname, "inject/poetry_simple")
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
			"expected requests@2.32.3 (from poetry.lock) not found in BOM")
	})

	// Poetry resolves from the network and writes a lock of its own when none is committed;
	// the stage must refuse before it gets the chance.
	It("fails the packages stage when poetry.lock is not committed", func(ctx SpecContext) {
		setupSbomBuildEnv()

		repoDirname := "repo_sbom_python_poetry_no_lock"
		SuiteData.InitTestRepo(ctx, repoDirname, "inject/poetry_simple")
		testRepoPath := SuiteData.GetTestRepoPath(repoDirname)
		utils.RunSucceedCommand(ctx, testRepoPath, "git", "rm", "-q", "poetry.lock")
		utils.RunSucceedCommand(ctx, testRepoPath, "git", "commit", "-q", "-m", "drop the lock")

		werfProject := werf.NewProject(SuiteData.WerfBinPath, testRepoPath)
		out, err := werfProject.BuildWithErr(ctx, &werf.BuildOptions{CommonOptions: werf.CommonOptions{}})
		Expect(err).To(HaveOccurred())
		Expect(out).To(ContainSubstring("lock file poetry.lock not found in /app; the packages stage installs only what the lock pins, commit it"))
		Expect(out).NotTo(ContainSubstring("Writing lock file"))
	})
})
