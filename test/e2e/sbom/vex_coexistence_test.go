package e2e_build_test

import (
	"os"
	"path/filepath"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/werf/werf/v2/pkg/attestation"
	"github.com/werf/werf/v2/pkg/vex"
	"github.com/werf/werf/v2/test/pkg/attestutils"
	"github.com/werf/werf/v2/test/pkg/report"
	"github.com/werf/werf/v2/test/pkg/utils"
	"github.com/werf/werf/v2/test/pkg/werf"
)

var _ = Describe("SBOM and VEX coexistence", Label("e2e", "sbom", "sbom-signing", "simple"), func() {
	It("US2: keeps both artifacts independently published, listed and superseded", func(ctx SpecContext) {
		By("initializing")
		setupSbomBuildEnv(setupEnvOptions{ContainerBackendMode: "vanilla-docker"})

		repoDirname := "repo_sbom_vex_coexistence"
		SuiteData.InitTestRepo(ctx, repoDirname, "signing_vex")
		testRepoPath := SuiteData.GetTestRepoPath(repoDirname)

		builderEnv := buildTrustedBuilderBase(ctx, testRepoPath, "sbom-vex-coexistence-builder")

		werfProject := werf.NewProject(SuiteData.WerfBinPath, testRepoPath)
		reportProject := report.NewProjectWithReport(werfProject)

		By("building without a key: both bare-DSSE artifacts coexist")
		_, buildReport := reportProject.BuildWithReport(ctx,
			SuiteData.GetBuildReportPath("sbom_vex_coexistence_unsigned.json"),
			&werf.WithReportOptions{CommonOptions: werf.CommonOptions{Envs: builderEnv}},
		)
		digest := buildReport.Images["app"].DockerImageDigest
		Expect(digest).NotTo(BeEmpty())

		repo := os.Getenv("WERF_REPO")
		Expect(repo).NotTo(BeEmpty())

		sbomDesc := attestutils.FindArtifactDescriptorByPredicate(ctx, repo, digest, attestation.DSSEMediaType, attestation.PredicateKindCycloneDX.UnsignedType)
		Expect(sbomDesc).NotTo(BeNil(), "unsigned SBOM artifact must be present")
		vexDesc := attestutils.FindArtifactDescriptorByPredicate(ctx, repo, digest, vex.DSSEMediaType, vex.VEXPredicateURI)
		Expect(vexDesc).NotTo(BeNil(), "unsigned VEX artifact must be present next to the SBOM")

		By("attest ls lists both kinds with their predicate types")
		lsOut := werfProject.AttestLs(ctx, &werf.AttestLsOptions{
			CommonOptions: werf.CommonOptions{
				ExtraArgs: []string{"--repo", repo, "--digest", digest},
			},
		})
		Expect(lsOut).To(ContainSubstring("cyclonedx"))
		Expect(lsOut).To(ContainSubstring("openvex"))

		By("building with a key: both signed bundles coexist, each superseding its own kind only")
		signKeys := generateSigningKeyPairWithCert(SuiteData.TmpDir)
		signEnv := append(builderEnv,
			"WERF_SIGN_KEY="+signKeys.KeyPath,
			"WERF_SIGN_CERT="+signKeys.CertPath,
		)
		werfProject.Build(ctx, &werf.BuildOptions{CommonOptions: werf.CommonOptions{Envs: signEnv}})

		sbomBundle := attestutils.FindArtifactDescriptorByPredicate(ctx, repo, digest, attestation.BundleMediaType, attestation.PredicateKindCycloneDX.SignedType)
		Expect(sbomBundle).NotTo(BeNil(), "signed SBOM bundle must be present")
		vexBundle := attestutils.FindArtifactDescriptorByPredicate(ctx, repo, digest, attestation.BundleMediaType, vex.VEXPredicateURIUnversioned)
		Expect(vexBundle).NotTo(BeNil(), "signed VEX bundle must be present next to the SBOM bundle")

		Expect(attestutils.FindArtifactDescriptorByPredicate(ctx, repo, digest, attestation.DSSEMediaType, attestation.PredicateKindCycloneDX.UnsignedType)).To(BeNil(),
			"stale unsigned SBOM artifact must be superseded")
		Expect(attestutils.FindArtifactDescriptorByPredicate(ctx, repo, digest, vex.DSSEMediaType, vex.VEXPredicateURI)).To(BeNil(),
			"stale unsigned VEX artifact must be superseded")

		By("both attestations are independently verifiable")
		sbomVerifyOut := werfProject.AttestVerify(ctx, &werf.AttestVerifyOptions{
			CommonOptions: werf.CommonOptions{
				ExtraArgs: []string{
					"--type", "cyclonedx",
					"--key", signKeys.PubKeyPath,
					"--repo", repo,
					"--digest", digest,
				},
			},
		})
		Expect(sbomVerifyOut).To(ContainSubstring("CycloneDX"))

		vexVerifyOut := werfProject.AttestVerify(ctx, &werf.AttestVerifyOptions{
			CommonOptions: werf.CommonOptions{
				ExtraArgs: []string{
					"--type", "openvex",
					"--key", signKeys.PubKeyPath,
					"--repo", repo,
					"--digest", digest,
				},
			},
		})
		Expect(vexVerifyOut).To(ContainSubstring("CVE-2024-E2E001"))

		By("changing only the VEX file republishes only the VEX artifact")
		sbomBundleDigestBefore := sbomBundle.Digest

		vexPath := filepath.Join(testRepoPath, "vex.openvex.json")
		vexContent, err := os.ReadFile(vexPath)
		Expect(err).NotTo(HaveOccurred())
		updated := []byte(string(vexContent[:len(vexContent)-2]) + `,
    {
      "vulnerability": {"name": "CVE-2024-E2E777"},
      "products": [{"@id": "pkg:oci/werf-test-app"}],
      "status": "fixed"
    }
  ]
}`)
		Expect(os.WriteFile(vexPath, updated, 0o644)).To(Succeed())
		utils.RunSucceedCommand(ctx, testRepoPath, "git", "add", "vex.openvex.json")
		utils.RunSucceedCommand(ctx, testRepoPath, "git", "commit", "-m", "update VEX document")

		rebuildOut := werfProject.Build(ctx, &werf.BuildOptions{CommonOptions: werf.CommonOptions{Envs: signEnv}})
		Expect(rebuildOut).To(ContainSubstring("Use previously generated SBOM from registry"))
		Expect(rebuildOut).To(ContainSubstring("Published VEX artifact"))

		sbomBundleAfter := attestutils.FindArtifactDescriptorByPredicate(ctx, repo, digest, attestation.BundleMediaType, attestation.PredicateKindCycloneDX.SignedType)
		Expect(sbomBundleAfter).NotTo(BeNil())
		Expect(sbomBundleAfter.Digest).To(Equal(sbomBundleDigestBefore), "SBOM artifact must stay byte-identical when only the VEX file changes")

		vexGetOut := werfProject.AttestGet(ctx, &werf.AttestGetOptions{
			CommonOptions: werf.CommonOptions{
				ExtraArgs: []string{
					"--type", "openvex",
					"--repo", repo,
					"--digest", digest,
				},
			},
		})
		Expect(vexGetOut).To(ContainSubstring("CVE-2024-E2E777"))
	})
})
