package e2e_build_test

import (
	"os"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/werf/werf/v2/pkg/attestation"
	"github.com/werf/werf/v2/pkg/image"
	"github.com/werf/werf/v2/test/pkg/attestutils"
	"github.com/werf/werf/v2/test/pkg/report"
	"github.com/werf/werf/v2/test/pkg/werf"
)

var _ = Describe("SBOM signing", Label("e2e", "sbom", "sbom-signing", "simple"), func() {
	DescribeTable("build with --sign-key publishes signed sigstore bundle verifiable offline",
		func(ctx SpecContext, testOpts sbomTestOptions) {
			By("initializing")
			setupSbomBuildEnv(testOpts.setupEnvOptions)

			repoDirname := "repo_sbom_signing"
			SuiteData.InitTestRepo(ctx, repoDirname, "signing")
			testRepoPath := SuiteData.GetTestRepoPath(repoDirname)

			builderEnv := buildTrustedBuilderBase(ctx, testRepoPath, "sbom-signing-builder")

			signKeys := generateSigningKeyPairWithCert(SuiteData.TmpDir)
			signEnv := append(builderEnv,
				"WERF_SIGN_KEY="+signKeys.KeyPath,
				"WERF_SIGN_CERT="+signKeys.CertPath,
			)

			By("building with --sign-key/--sign-cert")
			werfProject := werf.NewProject(SuiteData.WerfBinPath, testRepoPath)
			reportProject := report.NewProjectWithReport(werfProject)
			buildOut, buildReport := reportProject.BuildWithReport(ctx,
				SuiteData.GetBuildReportPath("sbom_signing.json"),
				&werf.WithReportOptions{CommonOptions: werf.CommonOptions{Envs: signEnv}},
			)
			Expect(buildOut).NotTo(ContainSubstring("multi-platform SBOM signing is not yet supported"))

			digest := buildReport.Images["app"].DockerImageDigest
			Expect(digest).NotTo(BeEmpty())

			repo := os.Getenv("WERF_REPO")
			Expect(repo).NotTo(BeEmpty())

			By("locating the bundle artifact in the fallback index")
			bundleDesc := attestutils.FindArtifactDescriptor(ctx, repo, digest, attestation.BundleMediaType)
			Expect(bundleDesc).NotTo(BeNil(), "no sigstore bundle artifact found in fallback index")
			Expect(bundleDesc.Annotations[image.WerfImageNameAnnotation]).To(Equal("app"))
			Expect(bundleDesc.Annotations[image.WerfChecksumAnnotation]).NotTo(BeEmpty())

			By("asserting no stale bare-DSSE artifact remains for the same image")
			dsseDesc := attestutils.FindArtifactDescriptor(ctx, repo, digest, attestation.DSSEMediaType)
			Expect(dsseDesc).To(BeNil(), "stale bare-DSSE artifact must be superseded by the bundle")

			By("fetching the bundle and verifying the DSSE signature with the public key")
			bundleJSON := attestutils.FetchArtifactLayerContent(ctx, repo, bundleDesc.Digest.String())

			envelopeJSON, err := attestation.UnwrapBundle(bundleJSON)
			Expect(err).NotTo(HaveOccurred())

			signed, err := attestation.HasSignatures(envelopeJSON)
			Expect(err).NotTo(HaveOccurred())
			Expect(signed).To(BeTrue(), "sbom dsse envelope must be signed")

			verifiers, err := attestation.LoadVerifiers([]string{signKeys.PubKeyPath})
			Expect(err).NotTo(HaveOccurred())

			stmtBytes, err := attestation.VerifyDSSE(ctx, envelopeJSON, attestation.InTotoMediaType, verifiers)
			Expect(err).NotTo(HaveOccurred(), "DSSE signature must verify with the signing public key")
			Expect(string(stmtBytes)).To(ContainSubstring(`"predicateType":"https://cyclonedx.org/bom"`))

			By("verifying the subject points to the image digest")
			Expect(string(stmtBytes)).To(ContainSubstring(digest[len("sha256:"):]))

			By("verifying via dk attest verify")
			verifyOut := werfProject.AttestVerify(ctx, &werf.AttestVerifyOptions{
				CommonOptions: werf.CommonOptions{
					ExtraArgs: []string{
						"--type", "cyclonedx",
						"--key", signKeys.PubKeyPath,
						"--repo", repo,
						"--digest", digest,
					},
				},
			})
			Expect(verifyOut).To(ContainSubstring("CycloneDX"))

			By("verifying offline with real cosign when available")
			runCosignOfflineVerify(ctx, repo, digest, signKeys.PubKeyPath)

			By("rebuilding unchanged - SBOM cache hit, no re-publication")
			rebuildOut := werfProject.Build(ctx, &werf.BuildOptions{CommonOptions: werf.CommonOptions{Envs: signEnv}})
			Expect(rebuildOut).To(ContainSubstring("Use previously generated SBOM from registry"))
		},
		Entry("with local repo using Vanilla Docker", sbomTestOptions{setupEnvOptions{ContainerBackendMode: "vanilla-docker"}}),
		Entry("with local repo using BuildKit Docker", sbomTestOptions{setupEnvOptions{ContainerBackendMode: "buildkit-docker"}}),
	)

	It("build without key keeps legacy unsigned bare-DSSE artifact", Label("e2e", "sbom", "sbom-signing", "unsigned"), func(ctx SpecContext) {
		setupSbomBuildEnv(setupEnvOptions{ContainerBackendMode: "vanilla-docker"})

		repoDirname := "repo_sbom_signing_unsigned"
		SuiteData.InitTestRepo(ctx, repoDirname, "signing")
		testRepoPath := SuiteData.GetTestRepoPath(repoDirname)

		builderEnv := buildTrustedBuilderBase(ctx, testRepoPath, "sbom-unsigned-builder")

		werfProject := werf.NewProject(SuiteData.WerfBinPath, testRepoPath)
		reportProject := report.NewProjectWithReport(werfProject)
		_, buildReport := reportProject.BuildWithReport(ctx,
			SuiteData.GetBuildReportPath("sbom_unsigned.json"),
			&werf.WithReportOptions{CommonOptions: werf.CommonOptions{Envs: builderEnv}},
		)

		digest := buildReport.Images["app"].DockerImageDigest
		repo := os.Getenv("WERF_REPO")

		dsseDesc := attestutils.FindArtifactDescriptor(ctx, repo, digest, attestation.DSSEMediaType)
		Expect(dsseDesc).NotTo(BeNil(), "unsigned build must keep the legacy bare-DSSE artifact")

		bundleDesc := attestutils.FindArtifactDescriptor(ctx, repo, digest, attestation.BundleMediaType)
		Expect(bundleDesc).To(BeNil(), "unsigned build must not produce a bundle artifact")

		envelopeJSON := attestutils.FetchArtifactLayerContent(ctx, repo, dsseDesc.Digest.String())
		signed, err := attestation.HasSignatures(envelopeJSON)
		Expect(err).NotTo(HaveOccurred())
		Expect(signed).To(BeFalse(), "unsigned build must produce an unsigned envelope")
	})

	It("build with key but without cert fails", Label("e2e", "sbom", "sbom-signing", "negative"), func(ctx SpecContext) {
		setupSbomBuildEnv(setupEnvOptions{ContainerBackendMode: "vanilla-docker"})

		repoDirname := "repo_sbom_signing_no_cert"
		SuiteData.InitTestRepo(ctx, repoDirname, "signing")
		testRepoPath := SuiteData.GetTestRepoPath(repoDirname)

		signKeys := generateSigningKeyPairWithCert(SuiteData.TmpDir)

		werfProject := werf.NewProject(SuiteData.WerfBinPath, testRepoPath)
		out := werfProject.Build(ctx, &werf.BuildOptions{
			CommonOptions: werf.CommonOptions{
				ShouldFail: true,
				Envs: []string{
					"BUILDER_BASE_IMAGE=registry.invalid/builder-base:stub",
					"WERF_SIGN_KEY=" + signKeys.KeyPath,
				},
			},
		})
		Expect(out).To(ContainSubstring("signing certificate is required"))
	})
})

type signingKeyPair = attestutils.SigningKeyPair

func generateSigningKeyPairWithCert(dir string) signingKeyPair {
	return attestutils.GenerateSigningKeyPairWithCert(dir)
}

// runCosignOfflineVerify verifies the SBOM attestation with stock cosign, offline.
func runCosignOfflineVerify(ctx SpecContext, repo, digest, pubKeyPath string) {
	attestutils.RunCosignOfflineVerify(ctx, attestutils.CosignVerifyOptions{
		Repo:          repo,
		Digest:        digest,
		PubKeyPath:    pubKeyPath,
		PredicateType: "cyclonedx",
		TmpDir:        SuiteData.TmpDir,
	})
}
