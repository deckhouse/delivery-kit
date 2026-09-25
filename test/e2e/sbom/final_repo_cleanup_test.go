package e2e_build_test

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/google/go-containerregistry/pkg/crane"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/werf/werf/v3/test/pkg/report"
	sbomtest "github.com/werf/werf/v3/test/pkg/sbom"
	"github.com/werf/werf/v3/test/pkg/suite_init"
	"github.com/werf/werf/v3/test/pkg/utils"
	"github.com/werf/werf/v3/test/pkg/werf"
)

var _ = Describe("SBOM retention across cleanup", Label("e2e", "sbom", "final-repo", "cleanup"), func() {
	It("cleanup keeps the SBOM of a retained image in both repos and collects it once the image is deleted", func(ctx SpecContext) {
		setupSbomBuildEnv()

		stagesRepo := suite_init.TestRepo(SuiteData.ProjectName)
		finalRepo := suite_init.TestRepo(SuiteData.ProjectName + "-final")
		SuiteData.Stubs.SetEnv("WERF_FINAL_REPO", finalRepo)

		repoDirname := "repo_sbom_final_repo_cleanup"
		SuiteData.InitTestRepo(ctx, repoDirname, "inject/ospm_basic")
		testRepoPath := SuiteData.GetTestRepoPath(repoDirname)

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

		stageTag := stageTagOf(ctx, werfProject, "app", builderEnv)

		assertSbomReadable := func(repo string, extraArgs ...string) {
			sbomOut := werfProject.SbomGet(ctx, &werf.SbomGetOptions{
				CommonOptions: werf.CommonOptions{
					ExtraArgs: append([]string{"--repo", repo}, extraArgs...),
					Envs:      builderEnv,
				},
			})
			sbomtest.AssertHasComponent(sbomtest.MustParseSBOMOutput(sbomOut), "curl", "8.12.1")
		}

		By("reading the SBOM from both repos before cleanup")
		assertSbomReadable(finalRepo, "--digest", finalDigest)
		assertSbomReadable(stagesRepo, "--tag", stageTag)

		// The keep list pins the stage without relying on git history reachability,
		// so the retention this spec asserts cannot pass because nothing was
		// eligible for deletion in the first place: the same run deletes every stage
		// that is not on the list.
		keepListPath := filepath.Join(testRepoPath, ".werf-keep-list")
		Expect(os.WriteFile(keepListPath, []byte(stageTag+"\n"), 0o600)).To(Succeed())

		// werf cleanup requires a git remote origin; it lives outside the project
		// directory so that it does not turn into an untracked file of the build.
		bareRemotePath := filepath.Join(SuiteData.TmpDir, "sbom_final_repo_cleanup_remote.git")
		utils.RunSucceedCommand(ctx, testRepoPath, "git", "init", "--bare", bareRemotePath)
		utils.RunSucceedCommand(ctx, testRepoPath, "git", "remote", "add", "origin", bareRemotePath)

		cleanupArgs := []string{"cleanup", "--without-kube", "--keep-stages-built-within-last-n-hours=0"}

		By("running cleanup twice while the stage is on the keep list")
		for range 2 {
			werfProject.RunCommand(ctx, append(append([]string{}, cleanupArgs...), "--keep-list", keepListPath),
				werf.CommonOptions{Envs: builderEnv})

			assertSbomReadable(finalRepo, "--digest", finalDigest)
			assertSbomReadable(stagesRepo, "--tag", stageTag)
		}

		By("running cleanup with nothing protecting the stage")
		werfProject.RunCommand(ctx, cleanupArgs, werf.CommonOptions{Envs: builderEnv})

		registryOptions := []crane.Option{crane.Insecure, crane.WithContext(ctx)}
		for _, repo := range []string{stagesRepo, finalRepo} {
			tags, err := crane.ListTags(repo, registryOptions...)
			Expect(err).NotTo(HaveOccurred())
			Expect(tags).NotTo(ContainElement(stageTag), "cleanup must have deleted the stage from %s", repo)
		}

		By("checking the orphaned SBOM artifacts were collected in both repos")
		expectNoSbomArtifact(ctx, stagesRepo, finalDigest)
		expectNoSbomArtifact(ctx, finalRepo, finalDigest)
	})
})

// stageTagOf returns the content-based tag of the image's last stage in the stages repo.
// werf stage image prints the reference as its last line, so the preceding log lines are dropped.
func stageTagOf(ctx SpecContext, werfProject *werf.Project, imageName string, envs []string) string {
	out := werfProject.RunCommand(ctx, []string{"stage", "image", imageName, "--log-quiet"}, werf.CommonOptions{Envs: envs})

	lines := strings.Split(strings.TrimSpace(out), "\n")
	ref := strings.TrimSpace(lines[len(lines)-1])
	Expect(ref).NotTo(BeEmpty(), "expected a stage image reference for %q, got output:\n%s", imageName, out)

	tag := ref[strings.LastIndex(ref, ":")+1:]
	Expect(tag).NotTo(BeEmpty(), "expected a tag in the stage image reference %q", ref)
	Expect(tag).NotTo(ContainSubstring("@"), "expected a tagged stage image reference, got %q", ref)

	return tag
}
