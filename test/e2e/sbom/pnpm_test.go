package e2e_build_test

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/werf/werf/v3/test/pkg/report"
	sbomtest "github.com/werf/werf/v3/test/pkg/sbom"
	"github.com/werf/werf/v3/test/pkg/utils"
	"github.com/werf/werf/v3/test/pkg/werf"
)

var _ = Describe("SBOM javascript-pnpm packages", Label("e2e", "sbom", "pnpm", "simple"), func() {
	It("catalogs pnpm-lock.yaml dependencies into the BOM with the pnpm the lock pins", func(ctx SpecContext) {
		setupSbomBuildEnv()

		repoDirname := "repo_sbom_pnpm_simple"
		SuiteData.InitTestRepo(ctx, repoDirname, "inject/pnpm_simple")
		testRepoPath := SuiteData.GetTestRepoPath(repoDirname)

		werfProject := werf.NewProject(SuiteData.WerfBinPath, testRepoPath)
		_, buildReport := report.NewProjectWithReport(werfProject).BuildWithReport(ctx,
			SuiteData.GetBuildReportPath("pnpm_simple.json"), &werf.WithReportOptions{},
		)
		Expect(buildReport.Images).To(HaveKey("app"))
		imageRef := buildReport.Images["app"].DockerImageName
		Expect(imageRef).NotTo(BeEmpty())

		sbomOut := werfProject.SbomGet(ctx, &werf.SbomGetOptions{
			CommonOptions: werf.CommonOptions{
				ExtraArgs: []string{"app"},
			},
		})

		bom := sbomtest.MustParseSBOMOutput(sbomOut)
		lodash := sbomtest.FindComponent(bom, "lodash", "4.17.21")
		Expect(lodash).NotTo(BeNil(),
			"expected lodash@4.17.21 (from pnpm-lock.yaml) not found in BOM")
		Expect(sbomtest.FindComponent(bom, "pnpm", "10.34.6")).NotTo(BeNil(),
			"expected the bootstrapped pnpm@10.34.6 not found in BOM")

		// The lock carries no license; syft reads it from the installed package's own
		// manifest under node_modules. pnpm exposes packages there only as symlinks into
		// its .pnpm store, so this also proves the link is resolved during extraction.
		sbomtest.AssertHasLicense(bom, "lodash", "4.17.21", "MIT")

		// package.json names another pnpm in packageManager; left to itself pnpm 10+
		// downloads that version and installs with it, recording it in .modules.yaml.
		modulesYAML, stderr, err := utils.RunCommandWithSeparateStreams(ctx, testRepoPath, "docker",
			[]string{"run", "--rm", "--network=none", "--entrypoint", "cat", imageRef, "/app/node_modules/.modules.yaml"},
			utils.RunCommandOptions{},
		)
		Expect(err).NotTo(HaveOccurred(), "read pnpm modules manifest: %s", stderr)
		Expect(string(modulesYAML)).To(MatchRegexp(`"?packageManager"?: "?pnpm@10\.34\.6\b`))
	})
})
