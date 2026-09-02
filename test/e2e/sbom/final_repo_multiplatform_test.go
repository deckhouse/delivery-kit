package e2e_build_test

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/werf/werf/v2/pkg/image"
	"github.com/werf/werf/v2/test/pkg/report"
	sbomtest "github.com/werf/werf/v2/test/pkg/sbom"
	"github.com/werf/werf/v2/test/pkg/suite_init"
	"github.com/werf/werf/v2/test/pkg/werf"
)

var _ = Describe("SBOM final repo multi-platform", Label("e2e", "sbom", "final-repo", "multiplatform"), func() {
	DescribeTable("build with --final-repo → per-platform SBOMs on platform manifest digests in both repos, none on the index",
		func(ctx SpecContext, testOpts sbomTestOptions) {
			setupSbomBuildEnv(testOpts.setupEnvOptions)

			stagesRepo := suite_init.TestRepo(SuiteData.ProjectName)
			finalRepo := suite_init.TestRepo(SuiteData.ProjectName + "-final")
			SuiteData.Stubs.SetEnv("WERF_FINAL_REPO", finalRepo)
			SuiteData.Stubs.SetEnv("WERF_ENABLE_REPORT_BY_PLATFORM", "1")
			SuiteData.Stubs.SetEnv("WERF_EXPERIMENTAL_STAPEL_ARM", "1")

			repoDirname := "repo_sbom_final_repo_multiplatform"
			SuiteData.InitTestRepo(ctx, repoDirname, "multiplatform")
			testRepoPath := SuiteData.GetTestRepoPath(repoDirname)

			By("building the multi-platform image with --final-repo")
			werfProject := werf.NewProject(SuiteData.WerfBinPath, testRepoPath)
			reportProject := report.NewProjectWithReport(werfProject)
			_, buildReport := reportProject.BuildWithReport(ctx,
				SuiteData.GetBuildReportPath("sbom_final_repo_multiplatform.json"), nil)

			appRecord, found := buildReport.Images["app"]
			Expect(found).To(BeTrue(), "expected image %q in build report", "app")
			Expect(appRecord.DockerRepo).To(Equal(finalRepo),
				"expected build report to reference the final repo")
			indexDigest := appRecord.DockerImageDigest
			Expect(indexDigest).NotTo(BeEmpty())

			byPlatform := buildReport.ImagesByPlatform["app"]
			Expect(byPlatform).To(HaveLen(len(multiplatformSbomPlatforms)), "expected a build report record per platform")

			// The registry-level index copy into the final repo preserves the digests
			// of the platform manifests it references, so the same platform digest
			// addresses the manifest in both repositories.
			By("verifying each platform manifest carries its SBOM in both repositories")
			for _, platform := range multiplatformSbomPlatforms {
				record, hasRecord := byPlatform[platform]
				Expect(hasRecord).To(BeTrue(), "no build report record for platform %s", platform)

				platformDigest := record.DockerImageDigest
				Expect(platformDigest).NotTo(BeEmpty())
				Expect(platformDigest).NotTo(Equal(indexDigest))

				stagesDesc, _ := fetchSingleSbomArtifact(ctx, stagesRepo, platformDigest)
				Expect(stagesDesc.Annotations[image.WerfPlatformAnnotation]).To(Equal(platform))

				finalDesc, _ := fetchSingleSbomArtifact(ctx, finalRepo, platformDigest)
				Expect(finalDesc.Annotations[image.WerfPlatformAnnotation]).To(Equal(platform))
			}

			By("verifying no SBOM artifact is attached to the index digest in either repository")
			expectNoSbomArtifact(ctx, stagesRepo, indexDigest)
			expectNoSbomArtifact(ctx, finalRepo, indexDigest)

			By("reading a platform SBOM from the final repo through the digest reported to the user")
			for _, platform := range multiplatformSbomPlatforms {
				sbomOut := werfProject.SbomGet(ctx, &werf.SbomGetOptions{
					CommonOptions: werf.CommonOptions{
						ExtraArgs: []string{
							"--repo", finalRepo,
							"--digest", indexDigest,
							"--platform", platform,
						},
					},
				})
				sbomtest.MustParseSBOMOutput(sbomOut)
			}
		},
		Entry("with final repo using Vanilla Docker", sbomTestOptions{setupEnvOptions{ContainerBackendMode: "vanilla-docker"}}),
		Entry("with final repo using BuildKit Docker", sbomTestOptions{setupEnvOptions{ContainerBackendMode: "buildkit-docker"}}),
	)
})
