package e2e_build_test

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/werf/werf/v2/test/pkg/report"
	sbomtest "github.com/werf/werf/v2/test/pkg/sbom"
	"github.com/werf/werf/v2/test/pkg/suite_init"
	"github.com/werf/werf/v2/test/pkg/werf"
)

var _ = Describe("SBOM final repo propagation", Label("e2e", "sbom", "final-repo"), func() {
	DescribeTable("build with --final-repo → sbom get from the final repo by digest",
		func(ctx SpecContext, testOpts sbomTestOptions) {
			setupSbomBuildEnv(testOpts.setupEnvOptions)

			finalRepo := suite_init.TestRepo(SuiteData.ProjectName + "-final")
			SuiteData.Stubs.SetEnv("WERF_FINAL_REPO", finalRepo)

			repoDirname := "repo_sbom_final_repo"
			SuiteData.InitTestRepo(ctx, repoDirname, "inject/ospm_basic")
			testRepoPath := SuiteData.GetTestRepoPath(repoDirname)

			builderEnv := buildTrustedBuilderBase(ctx, testRepoPath, "sbom-final-repo-builder")

			werfProject := werf.NewProject(SuiteData.WerfBinPath, testRepoPath)
			reportProject := report.NewProjectWithReport(werfProject)
			_, buildReport := reportProject.BuildWithReport(ctx,
				SuiteData.GetBuildReportPath("sbom_final_repo.json"),
				&werf.WithReportOptions{CommonOptions: werf.CommonOptions{Envs: builderEnv}},
			)

			appRecord, found := buildReport.Images["app"]
			Expect(found).To(BeTrue(), "expected image %q in build report", "app")
			Expect(appRecord.DockerRepo).To(Equal(finalRepo),
				"expected build report to reference the final repo")
			Expect(appRecord.DockerImageDigest).NotTo(BeEmpty())

			sbomOut := werfProject.SbomGet(ctx, &werf.SbomGetOptions{
				CommonOptions: werf.CommonOptions{
					ExtraArgs: []string{
						"--repo", finalRepo,
						"--digest", appRecord.DockerImageDigest,
					},
					Envs: builderEnv,
				},
			})

			bom := sbomtest.MustParseSBOMOutput(sbomOut)
			sbomtest.AssertHasComponent(bom, "curl", "8.12.1")
			sbomtest.AssertHasComponent(bom, "openssl", "3.6.2")
		},
		Entry("with final repo using Vanilla Docker", sbomTestOptions{setupEnvOptions{ContainerBackendMode: "vanilla-docker"}}),
		Entry("with final repo using BuildKit Docker", sbomTestOptions{setupEnvOptions{ContainerBackendMode: "buildkit-docker"}}),
	)
})
