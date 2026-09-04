package e2e_build_test

import (
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/werf/werf/v2/test/pkg/report"
	sbomtest "github.com/werf/werf/v2/test/pkg/sbom"
	"github.com/werf/werf/v2/test/pkg/suite_init"
	"github.com/werf/werf/v2/test/pkg/werf"
)

// The fixtures build from scratch on purpose: an image derived from a trusted
// builder base inherits the io.deckhouse.internal.builder label, and together
// with WERF_E2E_ALLOW_LOCAL_BUILDER_IMAGES a failed base SBOM lookup silently
// degrades into ErrSbomNotRequired instead of failing the build. A scratch
// base leaves no such escape, so these tables actually falsify the base/import
// SBOM lookup.
var _ = Describe("SBOM final repo with dependent images", Label("e2e", "sbom", "final-repo", "dependent"), func() {
	DescribeTable("image built from another image of the project: build with --final-repo succeeds",
		func(ctx SpecContext, testOpts sbomTestOptions) {
			setupSbomBuildEnv(testOpts.setupEnvOptions)

			finalRepo := suite_init.TestRepo(SuiteData.ProjectName + "-final")
			SuiteData.Stubs.SetEnv("WERF_FINAL_REPO", finalRepo)

			repoDirname := "repo_sbom_final_repo_dependent"
			SuiteData.InitTestRepo(ctx, repoDirname, "final_repo_dependent")
			testRepoPath := SuiteData.GetTestRepoPath(repoDirname)

			// The build itself is the primary assertion: SBOM convergence of the
			// dependent image has to find the SBOM of its base image, so a lookup
			// pointed at a repository that does not hold it fails the build.
			By("building the two dependent images with --final-repo against a clean registry")
			werfProject := werf.NewProject(SuiteData.WerfBinPath, testRepoPath)
			reportProject := report.NewProjectWithReport(werfProject)
			_, buildReport := reportProject.BuildWithReport(ctx,
				SuiteData.GetBuildReportPath("sbom_final_repo_dependent.json"), nil)

			appRecord, found := buildReport.Images["app"]
			Expect(found).To(BeTrue(), "expected image %q in build report", "app")
			Expect(appRecord.DockerRepo).To(Equal(finalRepo))
			Expect(appRecord.DockerImageDigest).NotTo(BeEmpty())

			By("reading the dependent image's SBOM from the final repo")
			sbomOut := werfProject.SbomGet(ctx, &werf.SbomGetOptions{
				CommonOptions: werf.CommonOptions{
					ExtraArgs: []string{"--repo", finalRepo, "--digest", appRecord.DockerImageDigest},
				},
			})
			sbomtest.MustParseSBOMOutput(sbomOut)

			By("rebuilding and checking the SBOMs are served from cache, not regenerated")
			rebuildOut := werfProject.Build(ctx, nil)
			Expect(strings.Count(rebuildOut, "Use previously generated SBOM from registry")).To(BeNumerically(">=", 2),
				"both the base and the dependent image SBOMs must be reused on rebuild")
		},
		Entry("with final repo using Vanilla Docker", sbomTestOptions{setupEnvOptions{ContainerBackendMode: "vanilla-docker"}}),
		Entry("with final repo using BuildKit Docker", sbomTestOptions{setupEnvOptions{ContainerBackendMode: "buildkit-docker"}}),
	)

	DescribeTable("image importing files from another image of the project: build with --final-repo succeeds",
		func(ctx SpecContext, testOpts sbomTestOptions) {
			setupSbomBuildEnv(testOpts.setupEnvOptions)

			finalRepo := suite_init.TestRepo(SuiteData.ProjectName + "-final")
			SuiteData.Stubs.SetEnv("WERF_FINAL_REPO", finalRepo)

			repoDirname := "repo_sbom_final_repo_import"
			SuiteData.InitTestRepo(ctx, repoDirname, "final_repo_import")
			testRepoPath := SuiteData.GetTestRepoPath(repoDirname)

			// SBOM convergence of the importing image has to find the SBOM of the
			// import source, exercising the import-side lookup the same way the
			// fromImage table exercises the base-image one.
			By("building the importing image with --final-repo against a clean registry")
			werfProject := werf.NewProject(SuiteData.WerfBinPath, testRepoPath)
			reportProject := report.NewProjectWithReport(werfProject)
			_, buildReport := reportProject.BuildWithReport(ctx,
				SuiteData.GetBuildReportPath("sbom_final_repo_import.json"), nil)

			appRecord, found := buildReport.Images["app"]
			Expect(found).To(BeTrue(), "expected image %q in build report", "app")
			Expect(appRecord.DockerImageDigest).NotTo(BeEmpty())

			By("reading the importing image's SBOM from the final repo")
			sbomOut := werfProject.SbomGet(ctx, &werf.SbomGetOptions{
				CommonOptions: werf.CommonOptions{
					ExtraArgs: []string{"--repo", finalRepo, "--digest", appRecord.DockerImageDigest},
				},
			})
			sbomtest.MustParseSBOMOutput(sbomOut)
		},
		Entry("with final repo using Vanilla Docker", sbomTestOptions{setupEnvOptions{ContainerBackendMode: "vanilla-docker"}}),
		Entry("with final repo using BuildKit Docker", sbomTestOptions{setupEnvOptions{ContainerBackendMode: "buildkit-docker"}}),
	)
})
