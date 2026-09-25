package e2e_build_test

import (
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/werf/werf/v3/pkg/attestation"
	"github.com/werf/werf/v3/pkg/image"
	"github.com/werf/werf/v3/test/pkg/report"
	sbomtest "github.com/werf/werf/v3/test/pkg/sbom"
	"github.com/werf/werf/v3/test/pkg/suite_init"
	"github.com/werf/werf/v3/test/pkg/werf"
)

// The fixtures build from scratch on purpose: an image derived from a trusted
// builder base inherits the io.deckhouse.internal.builder label, and together
// with WERF_E2E_ALLOW_LOCAL_BUILDER_IMAGES a failed base SBOM lookup silently
// degrades into ErrSbomNotRequired instead of failing the build. A scratch
// base leaves no such escape, so these specs actually falsify the base/import
// SBOM lookup.
var _ = Describe("SBOM final repo with dependent images", Label("e2e", "sbom", "final-repo", "dependent"), func() {
	It("image built from another image of the project: build with --final-repo succeeds", func(ctx SpecContext) {
		setupSbomBuildEnv()

		stagesRepo := suite_init.TestRepo(SuiteData.ProjectName)
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
		appDigest := appRecord.DockerImageDigest
		Expect(appDigest).NotTo(BeEmpty())

		assertAppSbomInFinalRepo(ctx, werfProject, finalRepo, appDigest)
		assertAppSbomInStagesRepo(ctx, werfProject, stagesRepo, "app")

		By("rebuilding and checking the SBOMs are served from cache, not regenerated")
		rebuildOut := werfProject.Build(ctx, nil)
		Expect(strings.Count(rebuildOut, "Use previously generated SBOM from registry")).To(BeNumerically(">=", 2),
			"both the base and the dependent image SBOMs must be reused on rebuild")
	})

	It("image importing files from another image of the project: build with --final-repo succeeds", func(ctx SpecContext) {
		setupSbomBuildEnv()

		stagesRepo := suite_init.TestRepo(SuiteData.ProjectName)
		finalRepo := suite_init.TestRepo(SuiteData.ProjectName + "-final")
		SuiteData.Stubs.SetEnv("WERF_FINAL_REPO", finalRepo)

		repoDirname := "repo_sbom_final_repo_import"
		SuiteData.InitTestRepo(ctx, repoDirname, "final_repo_import")
		testRepoPath := SuiteData.GetTestRepoPath(repoDirname)

		// SBOM convergence of the importing image has to find the SBOM of the
		// import source, exercising the import-side lookup the same way the
		// fromImage spec exercises the base-image one.
		By("building the importing image with --final-repo against a clean registry")
		werfProject := werf.NewProject(SuiteData.WerfBinPath, testRepoPath)
		reportProject := report.NewProjectWithReport(werfProject)
		_, buildReport := reportProject.BuildWithReport(ctx,
			SuiteData.GetBuildReportPath("sbom_final_repo_import.json"), nil)

		appRecord, found := buildReport.Images["app"]
		Expect(found).To(BeTrue(), "expected image %q in build report", "app")
		Expect(appRecord.DockerRepo).To(Equal(finalRepo))
		appDigest := appRecord.DockerImageDigest
		Expect(appDigest).NotTo(BeEmpty())

		assertAppSbomInFinalRepo(ctx, werfProject, finalRepo, appDigest)
		assertAppSbomInStagesRepo(ctx, werfProject, stagesRepo, "app")
	})
})

// assertAppSbomInFinalRepo checks the final repo serves the SBOM of that very image:
// the artifact index entry has to name the image and its in-toto subject has to be
// the digest the artifact is attached to, so an SBOM of another image of the same
// project — the base image is the one at hand — does not satisfy the assertion.
func assertAppSbomInFinalRepo(ctx SpecContext, werfProject *werf.Project, finalRepo, digest string) {
	By("reading the dependent image's SBOM from the final repo")

	desc, payload := fetchSingleSbomArtifact(ctx, finalRepo, digest)
	Expect(desc.ArtifactType).To(Equal(attestation.DSSEMediaType))
	Expect(desc.Annotations[image.WerfImageNameAnnotation]).To(Equal("app"))
	Expect(mustExtractInTotoSubjectDigest(payload)).To(Equal(digest))

	sbomOut := werfProject.SbomGet(ctx, &werf.SbomGetOptions{
		CommonOptions: werf.CommonOptions{
			ExtraArgs: []string{"--repo", finalRepo, "--digest", digest},
		},
	})
	sbomtest.MustParseSBOMOutput(sbomOut)
}

// assertAppSbomInStagesRepo reads the same SBOM out of the repository the image was
// built in, addressed by its stage tag: the presence of a copy in the final repo must
// not stand in for its absence here.
func assertAppSbomInStagesRepo(ctx SpecContext, werfProject *werf.Project, stagesRepo, imageName string) {
	By("reading the same image's SBOM from the stages repo")

	sbomOut := werfProject.SbomGet(ctx, &werf.SbomGetOptions{
		CommonOptions: werf.CommonOptions{
			ExtraArgs: []string{"--repo", stagesRepo, "--tag", stageTagOf(ctx, werfProject, imageName, nil)},
		},
	})
	sbomtest.MustParseSBOMOutput(sbomOut)
}
