package e2e_build_test

import (
	"os"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/werf/werf/v3/pkg/attestation"
	"github.com/werf/werf/v3/pkg/sbom/cyclonedxutil/gost"
	"github.com/werf/werf/v3/test/pkg/attestutils"
	"github.com/werf/werf/v3/test/pkg/report"
	sbomtest "github.com/werf/werf/v3/test/pkg/sbom"
	"github.com/werf/werf/v3/test/pkg/suite_init"
	"github.com/werf/werf/v3/test/pkg/werf"
)

var _ = Describe("SBOM signing downgrade", Label("e2e", "sbom", "sbom-signing", "unsigned", "simple"), func() {
	const (
		sbomCachedMarker = "Use previously generated SBOM from registry"
		sbomRegenMarker  = "SBOM processing"
	)

	It("build without the key supersedes the signed bundle and converges on the fresh SBOM", func(ctx SpecContext) {
		setupSbomBuildEnv()

		repoDirname := "repo_sbom_signing_downgrade"
		SuiteData.InitTestRepo(ctx, repoDirname, "gost_toggle/state0")
		testRepoPath := SuiteData.GetTestRepoPath(repoDirname)

		signKeys := generateSigningKeyPairWithCert(SuiteData.TmpDir)
		signEnv := []string{
			"WERF_SIGN_KEY=" + signKeys.KeyPath,
			"WERF_SIGN_CERT=" + signKeys.CertPath,
		}

		werfProject := werf.NewProject(SuiteData.WerfBinPath, testRepoPath)
		reportProject := report.NewProjectWithReport(werfProject)

		By("building with the signing key")
		_, buildReport := reportProject.BuildWithReport(ctx,
			SuiteData.GetBuildReportPath("sbom_signing_downgrade.json"),
			&werf.WithReportOptions{CommonOptions: werf.CommonOptions{Envs: signEnv}},
		)

		digest := buildReport.Images["app"].DockerImageDigest
		Expect(digest).NotTo(BeEmpty())

		repo := os.Getenv("WERF_REPO")
		Expect(repo).NotTo(BeEmpty())

		Expect(attestutils.FindArtifactDescriptor(ctx, repo, digest, attestation.BundleMediaType)).NotTo(BeNil(),
			"signed build must publish a sigstore bundle")

		By("rebuilding without the key and with a changed GOST config")
		SuiteData.UpdateTestRepo(ctx, repoDirname, "gost_toggle/state1")
		unsignedOut := werfProject.Build(ctx, nil)
		Expect(unsignedOut).To(ContainSubstring(sbomRegenMarker))

		Expect(attestutils.FindArtifactDescriptor(ctx, repo, digest, attestation.BundleMediaType)).To(BeNil(),
			"stale signed bundle must be superseded by the unsigned artifact")
		Expect(attestutils.FindArtifactDescriptor(ctx, repo, digest, attestation.DSSEMediaType)).NotTo(BeNil(),
			"unsigned build must publish a bare-DSSE artifact")

		By("reading the SBOM back")
		bom := sbomtest.MustParseSBOMOutput(werfProject.SbomGet(ctx, &werf.SbomGetOptions{
			CommonOptions: werf.CommonOptions{ExtraArgs: []string{"app"}},
		}))
		sbomtest.AssertGostPropertyOnMetadata(bom, gost.PropertyAttackSurface, gost.GostValueNo)
		sbomtest.AssertGostPropertyOnMetadata(bom, gost.PropertySecurityFunction, gost.GostValueNo)

		By("rebuilding unchanged - the SBOM cache converges")
		cachedOut := werfProject.Build(ctx, nil)
		Expect(cachedOut).To(ContainSubstring(sbomCachedMarker),
			"SBOM cache must converge after the key is removed; output:\n%s", cachedOut)
	})

	It("propagates the supersede into the final repo", Label("final-repo"), func(ctx SpecContext) {
		setupSbomBuildEnv()

		finalRepo := suite_init.TestRepo(SuiteData.ProjectName + "-final")
		SuiteData.Stubs.SetEnv("WERF_FINAL_REPO", finalRepo)

		repoDirname := "repo_sbom_signing_downgrade_final"
		SuiteData.InitTestRepo(ctx, repoDirname, "gost_toggle/state0")
		testRepoPath := SuiteData.GetTestRepoPath(repoDirname)

		signKeys := generateSigningKeyPairWithCert(SuiteData.TmpDir)
		signEnv := []string{
			"WERF_SIGN_KEY=" + signKeys.KeyPath,
			"WERF_SIGN_CERT=" + signKeys.CertPath,
		}

		werfProject := werf.NewProject(SuiteData.WerfBinPath, testRepoPath)
		reportProject := report.NewProjectWithReport(werfProject)

		By("building with the signing key")
		_, signedReport := reportProject.BuildWithReport(ctx,
			SuiteData.GetBuildReportPath("sbom_signing_downgrade_final_signed.json"),
			&werf.WithReportOptions{CommonOptions: werf.CommonOptions{Envs: signEnv}},
		)
		signedDigest := signedReport.Images["app"].DockerImageDigest
		Expect(signedDigest).NotTo(BeEmpty())
		Expect(attestutils.FindArtifactDescriptor(ctx, finalRepo, signedDigest, attestation.BundleMediaType)).NotTo(BeNil(),
			"signed build must propagate its bundle into the final repo")

		By("rebuilding without the key and with a changed GOST config")
		SuiteData.UpdateTestRepo(ctx, repoDirname, "gost_toggle/state1")
		_, unsignedReport := reportProject.BuildWithReport(ctx,
			SuiteData.GetBuildReportPath("sbom_signing_downgrade_final_unsigned.json"),
			&werf.WithReportOptions{CommonOptions: werf.CommonOptions{}},
		)
		unsignedDigest := unsignedReport.Images["app"].DockerImageDigest
		Expect(unsignedDigest).To(Equal(signedDigest),
			"the GOST change must not alter the image, otherwise the supersede assertion below is vacuous")

		Expect(attestutils.FindArtifactDescriptor(ctx, finalRepo, unsignedDigest, attestation.BundleMediaType)).To(BeNil(),
			"the final repo must mirror the supersede of the source repo")

		bom := sbomtest.MustParseSBOMOutput(werfProject.SbomGet(ctx, &werf.SbomGetOptions{
			CommonOptions: werf.CommonOptions{ExtraArgs: []string{"--repo", finalRepo, "--digest", unsignedDigest}},
		}))
		sbomtest.AssertGostPropertyOnMetadata(bom, gost.PropertyAttackSurface, gost.GostValueNo)
		sbomtest.AssertGostPropertyOnMetadata(bom, gost.PropertySecurityFunction, gost.GostValueNo)
	})
})
