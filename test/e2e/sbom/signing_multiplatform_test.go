package e2e_build_test

import (
	"os"
	"strings"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/werf/werf/v2/pkg/attestation"
	"github.com/werf/werf/v2/pkg/image"
	sbomImage "github.com/werf/werf/v2/pkg/sbom/image"
	"github.com/werf/werf/v2/test/pkg/report"
	"github.com/werf/werf/v2/test/pkg/werf"
)

var _ = Describe("SBOM multi-platform signing", Label("e2e", "sbom", "sbom-signing", "multiplatform", "simple"), func() {
	DescribeTable("multi-platform build with --sign-key publishes a signed sigstore bundle per platform",
		func(ctx SpecContext, testOpts sbomTestOptions) {
			By("initializing")
			setupSbomBuildEnv(testOpts.setupEnvOptions)

			repoDirname := "repo_sbom_signing_multiplatform"
			SuiteData.InitTestRepo(ctx, repoDirname, "signing_multiplatform")
			testRepoPath := SuiteData.GetTestRepoPath(repoDirname)

			SuiteData.Stubs.SetEnv("WERF_ENABLE_REPORT_BY_PLATFORM", "1")
			SuiteData.Stubs.SetEnv("WERF_EXPERIMENTAL_STAPEL_ARM", "1")

			signKeys := generateSigningKeyPairWithCert(SuiteData.TmpDir)
			signEnv := []string{
				"WERF_SIGN_KEY=" + signKeys.KeyPath,
				"WERF_SIGN_CERT=" + signKeys.CertPath,
			}

			By("building the multi-platform image with --sign-key/--sign-cert")
			werfProject := werf.NewProject(SuiteData.WerfBinPath, testRepoPath)
			reportProject := report.NewProjectWithReport(werfProject)
			buildOut, buildReport := reportProject.BuildWithReport(ctx,
				SuiteData.GetBuildReportPath("sbom_signing_multiplatform.json"),
				&werf.WithReportOptions{CommonOptions: werf.CommonOptions{Envs: signEnv}},
			)
			Expect(buildOut).NotTo(ContainSubstring("multi-platform SBOM signing is not yet supported"))

			repo := os.Getenv("WERF_REPO")
			Expect(repo).NotTo(BeEmpty())

			indexDigest := buildReport.Images["app"].DockerImageDigest
			Expect(indexDigest).NotTo(BeEmpty())

			byPlatform := buildReport.ImagesByPlatform["app"]
			Expect(byPlatform).To(HaveLen(len(multiplatformSbomPlatforms)), "expected a build report record per platform")

			verifiers, err := attestation.LoadVerifiers([]string{signKeys.PubKeyPath})
			Expect(err).NotTo(HaveOccurred())

			By("verifying each platform manifest carries exactly one signed bundle artifact")
			subjectDigests := map[string]string{}
			for _, platform := range multiplatformSbomPlatforms {
				record, hasRecord := byPlatform[platform]
				Expect(hasRecord).To(BeTrue(), "no build report record for platform %s", platform)

				platformDigest := record.DockerImageDigest
				Expect(platformDigest).NotTo(BeEmpty())
				Expect(platformDigest).NotTo(Equal(indexDigest))

				desc, payload := fetchSingleSbomArtifact(ctx, repo, platformDigest)
				Expect(desc.ArtifactType).To(Equal(attestation.BundleMediaType),
					"platform %s SBOM artifact must be a sigstore bundle", platform)
				Expect(desc.Annotations[image.WerfPlatformAnnotation]).To(Equal(platform))
				Expect(desc.Annotations[image.WerfImageNameAnnotation]).To(Equal("app"))
				Expect(desc.Annotations[image.WerfChecksumAnnotation]).NotTo(BeEmpty())

				envelopeJSON, err := attestation.UnwrapBundle(payload)
				Expect(err).NotTo(HaveOccurred())

				signed, err := attestation.HasSignatures(envelopeJSON)
				Expect(err).NotTo(HaveOccurred())
				Expect(signed).To(BeTrue(), "platform %s sbom dsse envelope must be signed", platform)

				stmtBytes, err := attestation.VerifyDSSE(ctx, envelopeJSON, attestation.InTotoMediaType, verifiers)
				Expect(err).NotTo(HaveOccurred(), "platform %s DSSE signature must verify with the signing public key", platform)
				Expect(string(stmtBytes)).To(ContainSubstring(`"predicateType":"https://cyclonedx.org/bom"`))

				subjectDigest := mustExtractInTotoSubjectDigest(envelopeJSON)
				Expect(subjectDigest).To(Equal(platformDigest),
					"platform %s in-toto subject must be the platform manifest digest", platform)
				subjectDigests[platform] = subjectDigest
			}

			Expect(subjectDigests["linux/amd64"]).NotTo(Equal(subjectDigests["linux/arm64"]),
				"platform SBOMs must attest distinct platform manifests")

			By("verifying no SBOM artifact is attached to the index digest")
			expectNoSbomArtifact(ctx, repo, indexDigest)

			By("verifying offline with real cosign per platform when available")
			for _, platform := range multiplatformSbomPlatforms {
				runCosignOfflineVerify(ctx, repo, byPlatform[platform].DockerImageDigest, signKeys.PubKeyPath)
			}

			attestVerifyArgs := func(pubKeyPath string, extraArgs ...string) []string {
				return append([]string{
					"--type", "cyclonedx",
					"--key", pubKeyPath,
					"--repo", repo,
					"--digest", indexDigest,
				}, extraArgs...)
			}

			By("verify-all: index reference without --platform verifies every platform")
			verifyAllOut := werfProject.AttestVerify(ctx, &werf.AttestVerifyOptions{
				CommonOptions: werf.CommonOptions{ExtraArgs: attestVerifyArgs(signKeys.PubKeyPath)},
			})
			for _, platform := range multiplatformSbomPlatforms {
				Expect(verifyAllOut).To(ContainSubstring(platform))
			}
			Expect(strings.Count(verifyAllOut, "verified")).To(BeNumerically(">=", len(multiplatformSbomPlatforms)))
			Expect(verifyAllOut).NotTo(ContainSubstring("invalid"))
			Expect(verifyAllOut).NotTo(ContainSubstring("missing"))

			By("verify-all: --platform narrows verification to one platform and dumps the predicate")
			singleOut := werfProject.AttestVerify(ctx, &werf.AttestVerifyOptions{
				CommonOptions: werf.CommonOptions{ExtraArgs: attestVerifyArgs(signKeys.PubKeyPath, "--platform", "linux/arm64")},
			})
			Expect(singleOut).To(ContainSubstring("CycloneDX"))

			By("verify-all: a wrong key fails verification for every platform")
			wrongKeys := generateSigningKeyPairWithCert(SuiteData.TmpDir)
			wrongKeyOut := werfProject.AttestVerify(ctx, &werf.AttestVerifyOptions{
				CommonOptions: werf.CommonOptions{ShouldFail: true, ExtraArgs: attestVerifyArgs(wrongKeys.PubKeyPath)},
			})
			Expect(wrongKeyOut).To(ContainSubstring("2 of 2 platforms"))
			Expect(wrongKeyOut).To(ContainSubstring("linux/amd64 (invalid)"))
			Expect(wrongKeyOut).To(ContainSubstring("linux/arm64 (invalid)"))

			By("rebuilding unchanged - per-platform SBOM cache hit, no re-publication")
			rebuildOut := werfProject.Build(ctx, &werf.BuildOptions{CommonOptions: werf.CommonOptions{Envs: signEnv}})
			Expect(strings.Count(rebuildOut, "Use previously generated SBOM from registry")).To(BeNumerically(">=", len(multiplatformSbomPlatforms)),
				"each platform SBOM must be served from cache on rebuild with the same key")

			By("rebuilding with a rotated key - cache miss and re-sign for every platform")
			rotatedKeys := generateSigningKeyPairWithCert(SuiteData.TmpDir)
			rotatedEnv := []string{
				"WERF_SIGN_KEY=" + rotatedKeys.KeyPath,
				"WERF_SIGN_CERT=" + rotatedKeys.CertPath,
			}
			rotatedOut := werfProject.Build(ctx, &werf.BuildOptions{CommonOptions: werf.CommonOptions{Envs: rotatedEnv}})
			Expect(rotatedOut).NotTo(ContainSubstring("Use previously generated SBOM from registry"),
				"rotating the key must invalidate every platform SBOM cache")

			verifyRotatedOut := werfProject.AttestVerify(ctx, &werf.AttestVerifyOptions{
				CommonOptions: werf.CommonOptions{ExtraArgs: attestVerifyArgs(rotatedKeys.PubKeyPath)},
			})
			Expect(strings.Count(verifyRotatedOut, "verified")).To(BeNumerically(">=", len(multiplatformSbomPlatforms)))

			By("verify-all: a platform without an attestation is classified as missing")
			arm64FallbackRef, err := name.NewTag(repo+":"+sbomImage.FallbackTag(byPlatform["linux/arm64"].DockerImageDigest), name.Insecure)
			Expect(err).NotTo(HaveOccurred())
			Expect(remote.WriteIndex(arm64FallbackRef, empty.Index,
				remote.WithContext(ctx), remote.WithAuth(authn.Anonymous))).To(Succeed())

			missingOut := werfProject.AttestVerify(ctx, &werf.AttestVerifyOptions{
				CommonOptions: werf.CommonOptions{ShouldFail: true, ExtraArgs: attestVerifyArgs(rotatedKeys.PubKeyPath)},
			})
			Expect(missingOut).To(ContainSubstring("1 of 2 platforms"))
			Expect(missingOut).To(ContainSubstring("linux/arm64 (missing)"))
			Expect(missingOut).NotTo(ContainSubstring("linux/amd64 (missing)"))
		},
		Entry("with local repo using Vanilla Docker", sbomTestOptions{setupEnvOptions{ContainerBackendMode: "vanilla-docker"}}),
		Entry("with local repo using BuildKit Docker", sbomTestOptions{setupEnvOptions{ContainerBackendMode: "buildkit-docker"}}),
	)

	It("multi-platform build without key keeps unsigned bare-DSSE per platform, enabling the key supersedes them", Label("e2e", "sbom", "sbom-signing", "multiplatform", "unsigned"), func(ctx SpecContext) {
		setupSbomBuildEnv(setupEnvOptions{ContainerBackendMode: "vanilla-docker"})

		repoDirname := "repo_sbom_signing_multiplatform_unsigned"
		SuiteData.InitTestRepo(ctx, repoDirname, "signing_multiplatform")
		testRepoPath := SuiteData.GetTestRepoPath(repoDirname)

		SuiteData.Stubs.SetEnv("WERF_ENABLE_REPORT_BY_PLATFORM", "1")
		SuiteData.Stubs.SetEnv("WERF_EXPERIMENTAL_STAPEL_ARM", "1")

		By("building the multi-platform image without a signing key")
		werfProject := werf.NewProject(SuiteData.WerfBinPath, testRepoPath)
		reportProject := report.NewProjectWithReport(werfProject)
		buildOut, buildReport := reportProject.BuildWithReport(ctx,
			SuiteData.GetBuildReportPath("sbom_signing_multiplatform_unsigned.json"), nil)
		Expect(buildOut).NotTo(ContainSubstring("multi-platform SBOM signing is not yet supported"))

		repo := os.Getenv("WERF_REPO")
		byPlatform := buildReport.ImagesByPlatform["app"]
		Expect(byPlatform).To(HaveLen(len(multiplatformSbomPlatforms)))

		By("verifying each platform keeps the legacy unsigned bare-DSSE artifact")
		for _, platform := range multiplatformSbomPlatforms {
			desc, payload := fetchSingleSbomArtifact(ctx, repo, byPlatform[platform].DockerImageDigest)
			Expect(desc.ArtifactType).To(Equal(attestation.DSSEMediaType),
				"platform %s must keep the legacy bare-DSSE artifact", platform)

			signed, err := attestation.HasSignatures(payload)
			Expect(err).NotTo(HaveOccurred())
			Expect(signed).To(BeFalse(), "platform %s envelope must be unsigned", platform)
		}

		By("rebuilding with a signing key - cache miss, signed bundles supersede the bare-DSSE artifacts")
		signKeys := generateSigningKeyPairWithCert(SuiteData.TmpDir)
		signEnv := []string{
			"WERF_SIGN_KEY=" + signKeys.KeyPath,
			"WERF_SIGN_CERT=" + signKeys.CertPath,
		}
		rebuildOut := werfProject.Build(ctx, &werf.BuildOptions{CommonOptions: werf.CommonOptions{Envs: signEnv}})
		Expect(rebuildOut).NotTo(ContainSubstring("Use previously generated SBOM from registry"),
			"enabling signing must invalidate every platform SBOM cache")

		for _, platform := range multiplatformSbomPlatforms {
			desc, payload := fetchSingleSbomArtifact(ctx, repo, byPlatform[platform].DockerImageDigest)
			Expect(desc.ArtifactType).To(Equal(attestation.BundleMediaType),
				"platform %s bare-DSSE artifact must be superseded by the signed bundle", platform)

			envelopeJSON, err := attestation.UnwrapBundle(payload)
			Expect(err).NotTo(HaveOccurred())

			signed, err := attestation.HasSignatures(envelopeJSON)
			Expect(err).NotTo(HaveOccurred())
			Expect(signed).To(BeTrue(), "platform %s envelope must be signed after enabling the key", platform)
		}
	})
})
