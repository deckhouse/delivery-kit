package e2e_build_test

import (
	"strings"

	cdx "github.com/CycloneDX/cyclonedx-go"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/werf/werf/v3/pkg/attestation"
	"github.com/werf/werf/v3/pkg/image"
	"github.com/werf/werf/v3/pkg/vex"
	"github.com/werf/werf/v3/test/pkg/attestutils"
	"github.com/werf/werf/v3/test/pkg/report"
	sbomtest "github.com/werf/werf/v3/test/pkg/sbom"
	"github.com/werf/werf/v3/test/pkg/suite_init"
	"github.com/werf/werf/v3/test/pkg/werf"
)

var _ = Describe("SBOM and VEX across every repository of a build", Label("e2e", "sbom", "final-repo", "sweep"), func() {
	It("reuses stages from a secondary repo and still serves SBOM and VEX from the stages and the final repo", func(ctx SpecContext) {
		setupSbomBuildEnv()

		repoDirname := "repo_sbom_final_repo_sweep"
		SuiteData.InitTestRepo(ctx, repoDirname, "final_repo_sweep")
		testRepoPath := SuiteData.GetTestRepoPath(repoDirname)
		for _, envVar := range buildTrustedBuilderBase(ctx, testRepoPath, "sbom-final-repo-sweep-builder") {
			key, value, found := strings.Cut(envVar, "=")
			Expect(found).To(BeTrue())
			SuiteData.Stubs.SetEnv(key, value)
		}

		werfProject := werf.NewProject(SuiteData.WerfBinPath, testRepoPath)
		reportProject := report.NewProjectWithReport(werfProject)

		secondaryRepo := suite_init.TestRepo(SuiteData.ProjectName + "-secondary")
		stagesRepo := suite_init.TestRepo(SuiteData.ProjectName + "-stages")
		finalRepo := suite_init.TestRepo(SuiteData.ProjectName + "-final")
		cacheRepo := suite_init.TestRepo(SuiteData.ProjectName + "-cache")

		By("seeding a secondary repo with a full build")
		SuiteData.Stubs.SetEnv("WERF_REPO", secondaryRepo)
		werfProject.Build(ctx, nil)

		By("rebuilding into a clean stages repo, reusing the secondary repo and publishing to a final repo")
		SuiteData.Stubs.SetEnv("WERF_REPO", stagesRepo)
		SuiteData.Stubs.SetEnv("WERF_SECONDARY_REPO_1", secondaryRepo)
		SuiteData.Stubs.SetEnv("WERF_FINAL_REPO", finalRepo)
		SuiteData.Stubs.SetEnv("WERF_CACHE_REPO_1", cacheRepo)

		_, buildReport := reportProject.BuildWithReport(ctx,
			SuiteData.GetBuildReportPath("sbom_final_repo_sweep.json"), nil)

		for _, imageName := range []string{"base", "carrier", "app"} {
			record, found := buildReport.Images[imageName]
			Expect(found).To(BeTrue(), "expected image %q in build report", imageName)
			Expect(record.StagesSkipped).To(BeTrue(),
				"image %q must be reused from the secondary repo by content-based tag, not rebuilt", imageName)
		}

		appRecord := buildReport.Images["app"]
		Expect(appRecord.DockerRepo).To(Equal(finalRepo))
		appDigest := appRecord.DockerImageDigest
		Expect(appDigest).NotTo(BeEmpty())

		By("the final repo serves this image's own SBOM, and it carries what the base and the import source contributed")
		desc, payload := fetchSingleSbomArtifact(ctx, finalRepo, appDigest)
		Expect(desc.ArtifactType).To(Equal(attestation.DSSEMediaType))
		Expect(desc.Annotations[image.WerfImageNameAnnotation]).To(Equal("app"))
		Expect(mustExtractInTotoSubjectDigest(payload)).To(Equal(appDigest))

		finalSbomOut := werfProject.SbomGet(ctx, &werf.SbomGetOptions{
			CommonOptions: werf.CommonOptions{ExtraArgs: []string{"--repo", finalRepo, "--digest", appDigest}},
		})
		finalBom := sbomtest.MustParseSBOMOutput(finalSbomOut)
		assertCarriesImportedComponents(ctx, werfProject, stagesRepo, finalBom)

		By("the stages repo serves the same SBOM on its own, not by proxy of the final repo")
		stagesSbomOut := werfProject.SbomGet(ctx, &werf.SbomGetOptions{
			CommonOptions: werf.CommonOptions{ExtraArgs: []string{"--repo", stagesRepo, "--tag", stageTagOf(ctx, werfProject, "app", nil)}},
		})
		assertCarriesImportedComponents(ctx, werfProject, stagesRepo, sbomtest.MustParseSBOMOutput(stagesSbomOut))

		By("VEX is available next to the image in both the stages and the final repo")
		Expect(attestutils.FindArtifactDescriptorByPredicate(ctx, finalRepo, appDigest, vex.DSSEMediaType, vex.VEXPredicateURI)).NotTo(BeNil(),
			"the final repo must serve the VEX document of the image it publishes")

		stagesDigest := stagesImageDigestOf(ctx, werfProject, "app")
		Expect(attestutils.FindArtifactDescriptorByPredicate(ctx, stagesRepo, stagesDigest, vex.DSSEMediaType, vex.VEXPredicateURI)).NotTo(BeNil(),
			"the stages repo must serve the VEX document on its own")

		By("the cache repo holds the stage under the stages repo digest and serves its SBOM and VEX")
		cacheDesc, cachePayload := fetchSingleSbomArtifact(ctx, cacheRepo, stagesDigest)
		Expect(cacheDesc.Annotations[image.WerfImageNameAnnotation]).To(Equal("app"))
		Expect(mustExtractInTotoSubjectDigest(cachePayload)).To(Equal(stagesDigest))
		Expect(attestutils.FindArtifactDescriptorByPredicate(ctx, cacheRepo, stagesDigest, vex.DSSEMediaType, vex.VEXPredicateURI)).NotTo(BeNil(),
			"the cache repo must serve the VEX document of the stage it mirrors")
	})
})

// assertCarriesImportedComponents checks the SBOM of app contains everything the
// SBOMs of its base image and its import source list. app is a Stapel image with
// no packages directive, so it is never scanned on its own: a component of either
// source can only have reached it through the merge of that image's SBOM. base
// (Go module) and carrier (Cargo) catalog different ecosystems, so each side of
// the merge is discriminated on its own.
func assertCarriesImportedComponents(ctx SpecContext, werfProject *werf.Project, stagesRepo string, appBom *cdx.BOM) {
	for _, source := range []string{"base", "carrier"} {
		sourceSbomOut := werfProject.SbomGet(ctx, &werf.SbomGetOptions{
			CommonOptions: werf.CommonOptions{ExtraArgs: []string{"--repo", stagesRepo, "--tag", stageTagOf(ctx, werfProject, source, nil)}},
		})
		sourceBom := sbomtest.MustParseSBOMOutput(sourceSbomOut)

		Expect(sourceBom.Components).NotTo(BeNil())
		Expect(*sourceBom.Components).NotTo(BeEmpty(), "image %q must contribute components for this assertion to discriminate", source)

		for _, component := range *sourceBom.Components {
			Expect(sbomtest.FindComponentByPURL(appBom, component.PackageURL)).NotTo(BeNil(),
				"component %s of image %q is missing from the merged SBOM", component.PackageURL, source)
		}
	}
}
