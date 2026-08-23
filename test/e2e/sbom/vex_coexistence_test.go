package e2e_build_test

import (
	"os"
	"path/filepath"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/werf/werf/v2/pkg/attestation"
	"github.com/werf/werf/v2/pkg/oci/artifact"
	"github.com/werf/werf/v2/pkg/vex"
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

		sbomDesc := findArtifactDescriptorByPredicate(ctx, repo, digest, attestation.DSSEMediaType, sbomCycloneDX16Predicate)
		Expect(sbomDesc).NotTo(BeNil(), "unsigned SBOM artifact must be present")
		vexDesc := findArtifactDescriptorByPredicate(ctx, repo, digest, vex.DSSEMediaType, vex.VEXPredicateURI)
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

		sbomBundle := findArtifactDescriptorByPredicate(ctx, repo, digest, attestation.BundleMediaType, sbomCycloneDXPredicate)
		Expect(sbomBundle).NotTo(BeNil(), "signed SBOM bundle must be present")
		vexBundle := findArtifactDescriptorByPredicate(ctx, repo, digest, attestation.BundleMediaType, vex.VEXPredicateURIUnversioned)
		Expect(vexBundle).NotTo(BeNil(), "signed VEX bundle must be present next to the SBOM bundle")

		Expect(findArtifactDescriptorByPredicate(ctx, repo, digest, attestation.DSSEMediaType, sbomCycloneDX16Predicate)).To(BeNil(),
			"stale unsigned SBOM artifact must be superseded")
		Expect(findArtifactDescriptorByPredicate(ctx, repo, digest, vex.DSSEMediaType, vex.VEXPredicateURI)).To(BeNil(),
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

		sbomBundleAfter := findArtifactDescriptorByPredicate(ctx, repo, digest, attestation.BundleMediaType, sbomCycloneDXPredicate)
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

const (
	sbomCycloneDXPredicate   = "https://cyclonedx.org/bom"
	sbomCycloneDX16Predicate = "https://cyclonedx.org/bom/v1.6"
)

func findArtifactDescriptorByPredicate(ctx SpecContext, repo, parentDigest, artifactType, predicateType string) *v1.Descriptor {
	tagRef, err := name.NewTag(repo+":"+artifact.FallbackTag(parentDigest), name.Insecure)
	ExpectWithOffset(1, err).NotTo(HaveOccurred())

	ropts := []remote.Option{remote.WithContext(ctx), remote.WithAuth(authn.Anonymous)}

	idx, err := remote.Index(tagRef, ropts...)
	if err != nil {
		return nil
	}

	im, err := idx.IndexManifest()
	ExpectWithOffset(1, err).NotTo(HaveOccurred())

	for _, desc := range im.Manifests {
		if desc.ArtifactType == artifactType && desc.Annotations[artifact.PredicateTypeAnnotation] == predicateType {
			found := desc
			return &found
		}
	}
	return nil
}
