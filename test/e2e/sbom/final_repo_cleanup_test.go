package e2e_build_test

import (
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/werf/werf/v2/test/pkg/report"
	sbomtest "github.com/werf/werf/v2/test/pkg/sbom"
	"github.com/werf/werf/v2/test/pkg/suite_init"
	"github.com/werf/werf/v2/test/pkg/utils"
	"github.com/werf/werf/v2/test/pkg/werf"
)

var _ = Describe("SBOM retention across cleanup", Label("e2e", "sbom", "final-repo", "cleanup"), func() {
	DescribeTable("build with --final-repo → cleanup → SBOM still readable from both repos",
		func(ctx SpecContext, testOpts sbomTestOptions) {
			setupSbomBuildEnv(testOpts.setupEnvOptions)

			stagesRepo := suite_init.TestRepo(SuiteData.ProjectName)
			finalRepo := suite_init.TestRepo(SuiteData.ProjectName + "-final")
			SuiteData.Stubs.SetEnv("WERF_FINAL_REPO", finalRepo)

			repoDirname := "repo_sbom_final_repo_cleanup"
			SuiteData.InitTestRepo(ctx, repoDirname, "inject/ospm_basic")
			testRepoPath := SuiteData.GetTestRepoPath(repoDirname)

			// werf cleanup keeps an image only while the commit it was built from stays
			// reachable from a remote branch. Without origin every image looks unreachable
			// and gets deleted, which would hide the retention this test asserts.
			// The bare remote lives outside the work tree: the fixture adds the whole
			// project directory to the image, so an in-tree remote would break giterminism.
			remotePath := SuiteData.GetTestRepoPath(repoDirname + "_remote.git")
			utils.RunSucceedCommand(ctx, testRepoPath, "git", "init", "--bare", remotePath)
			utils.RunSucceedCommand(ctx, testRepoPath, "git", "remote", "add", "origin", remotePath)
			utils.RunSucceedCommand(ctx, testRepoPath, "git", "push", "--set-upstream", "origin", "HEAD:refs/heads/main")

			builderEnv := buildTrustedBuilderBase(ctx, testRepoPath, "sbom-final-repo-cleanup-builder")

			werfProject := werf.NewProject(SuiteData.WerfBinPath, testRepoPath)
			reportProject := report.NewProjectWithReport(werfProject)
			_, buildReport := reportProject.BuildWithReport(ctx,
				SuiteData.GetBuildReportPath("sbom_final_repo_cleanup.json"),
				&werf.WithReportOptions{CommonOptions: werf.CommonOptions{Envs: builderEnv}},
			)

			appRecord, found := buildReport.Images["app"]
			Expect(found).To(BeTrue(), "expected image %q in build report", "app")
			Expect(appRecord.DockerRepo).To(Equal(finalRepo),
				"expected build report to reference the final repo")
			finalDigest := appRecord.DockerImageDigest
			Expect(finalDigest).NotTo(BeEmpty())

			// The stage copy into the final repo may change the manifest digest, so the
			// stages repo has to be addressed by its own stage tag rather than by finalDigest.
			stageTag := stageTagOf(ctx, werfProject, "app", builderEnv)

			assertSbomInFinalRepo := func() {
				sbomOut := werfProject.SbomGet(ctx, &werf.SbomGetOptions{
					CommonOptions: werf.CommonOptions{
						ExtraArgs: []string{"--repo", finalRepo, "--digest", finalDigest},
						Envs:      builderEnv,
					},
				})
				sbomtest.AssertHasComponent(sbomtest.MustParseSBOMOutput(sbomOut), "curl", "8.12.1")
			}

			assertSbomInStagesRepo := func() {
				sbomOut := werfProject.SbomGet(ctx, &werf.SbomGetOptions{
					CommonOptions: werf.CommonOptions{
						ExtraArgs: []string{"--repo", stagesRepo, "--tag", stageTag},
						Envs:      builderEnv,
					},
				})
				sbomtest.AssertHasComponent(sbomtest.MustParseSBOMOutput(sbomOut), "curl", "8.12.1")
			}

			By("reading the SBOM from both repos before cleanup")
			assertSbomInFinalRepo()
			assertSbomInStagesRepo()

			By("running cleanup while the image is still in use")
			werfProject.RunCommand(ctx, []string{"cleanup", "--without-kube"}, werf.CommonOptions{Envs: builderEnv})

			By("reading the SBOM from both repos after cleanup")
			assertSbomInFinalRepo()
			assertSbomInStagesRepo()

			By("running cleanup a second time")
			werfProject.RunCommand(ctx, []string{"cleanup", "--without-kube"}, werf.CommonOptions{Envs: builderEnv})

			By("reading the SBOM from both repos after the repeated cleanup")
			assertSbomInFinalRepo()
			assertSbomInStagesRepo()
		},
		Entry("with final repo using Vanilla Docker", sbomTestOptions{setupEnvOptions{ContainerBackendMode: "vanilla-docker"}}),
		Entry("with final repo using BuildKit Docker", sbomTestOptions{setupEnvOptions{ContainerBackendMode: "buildkit-docker"}}),
	)
})

// stageTagOf returns the content-based tag of the image's last stage in the stages repo.
// werf stage image prints the reference as its last line, so the preceding log lines are dropped.
func stageTagOf(ctx SpecContext, werfProject *werf.Project, imageName string, envs []string) string {
	out := werfProject.RunCommand(ctx, []string{"stage", "image", imageName, "--log-quiet"}, werf.CommonOptions{Envs: envs})

	lines := strings.Split(strings.TrimSpace(out), "\n")
	ref := strings.TrimSpace(lines[len(lines)-1])
	Expect(ref).NotTo(BeEmpty(), "expected a stage image reference for %q, got output:\n%s", imageName, out)

	parts := strings.Split(ref, ":")
	tag := parts[len(parts)-1]
	Expect(tag).NotTo(BeEmpty(), "expected a tag in the stage image reference %q", ref)

	return tag
}
