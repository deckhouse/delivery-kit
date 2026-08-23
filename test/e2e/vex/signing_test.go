package e2e_vex_test

import (
	"io"
	"path/filepath"

	"github.com/deckhouse/delivery-kit-sdk/test/pkg/cert_utils"
	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/sigstore/sigstore/pkg/cryptoutils"

	"github.com/werf/werf/v2/pkg/attestation"
	"github.com/werf/werf/v2/pkg/image"
	"github.com/werf/werf/v2/pkg/oci/artifact"
	"github.com/werf/werf/v2/pkg/vex"
	"github.com/werf/werf/v2/test/pkg/suite_init"
	"github.com/werf/werf/v2/test/pkg/werf"
)

var _ = Describe("VEX signing", Label("e2e", "VEX", "signing", "simple"), func() {
	It("US1/US4/US5: signs the VEX artifact, keeps the cache honest, verifies via attest verify", func(ctx SpecContext) {
		setupVexEnv("vanilla-docker")

		repoDirname := "repo_vex_signing"
		SuiteData.InitTestRepo(ctx, repoDirname, "simple")
		testRepoPath := SuiteData.GetTestRepoPath(repoDirname)

		werfProject := werf.NewProject(SuiteData.WerfBinPath, testRepoPath)
		repo := suite_init.TestRepo(SuiteData.ProjectName)

		signKeys := generateVexSigningKeyPairWithCert(SuiteData.TmpDir)
		otherKeys := generateVexSigningKeyPairWithCert(SuiteData.TmpDir)
		signEnv := []string{
			"WERF_SIGN_KEY=" + signKeys.KeyPath,
			"WERF_SIGN_CERT=" + signKeys.CertPath,
		}

		By("US4: building without a key publishes the unsigned artifact")
		buildReportPath := filepath.Join(SuiteData.TmpDir, "vex_signing_unsigned.json")
		werfProject.Build(ctx, &werf.BuildOptions{
			CommonOptions: werf.CommonOptions{
				ExtraArgs: []string{"--save-build-report", "--build-report-path", buildReportPath},
			},
		})
		digest := readDigestFromReport(buildReportPath, "app")

		dsseDesc := findVexArtifactDescriptor(ctx, repo, digest, vex.DSSEMediaType)
		Expect(dsseDesc).NotTo(BeNil(), "keyless build must publish the bare-DSSE VEX artifact")

		By("US5: attest verify classifies the unsigned artifact distinctly")
		verifyOut := werfProject.AttestVerify(ctx, &werf.AttestVerifyOptions{
			CommonOptions: werf.CommonOptions{
				ShouldFail: true,
				ExtraArgs: []string{
					"--type", "openvex",
					"--key", signKeys.PubKeyPath,
					"--repo", repo,
					"--digest", digest,
				},
			},
		})
		Expect(verifyOut).To(ContainSubstring("present but unsigned (legacy format)"))

		By("US4: rebuilding with a key republishes a signed bundle superseding the bare-DSSE artifact")
		buildOut := werfProject.Build(ctx, &werf.BuildOptions{CommonOptions: werf.CommonOptions{Envs: signEnv}})
		Expect(buildOut).To(ContainSubstring("Published VEX artifact"))

		bundleDesc := findVexArtifactDescriptor(ctx, repo, digest, attestation.BundleMediaType)
		Expect(bundleDesc).NotTo(BeNil(), "signed build must publish the sigstore bundle VEX artifact")
		Expect(bundleDesc.Annotations[image.WerfImageNameAnnotation]).To(Equal("app"))
		Expect(bundleDesc.Annotations[artifact.PredicateTypeAnnotation]).To(Equal(vex.VEXPredicateURIUnversioned))

		Expect(findVexArtifactDescriptor(ctx, repo, digest, vex.DSSEMediaType)).To(BeNil(),
			"stale bare-DSSE VEX artifact must be superseded by the bundle")

		By("US1: the bundle envelope is signed and its subject is the image digest")
		bundleJSON := fetchVexArtifactLayerContent(ctx, repo, bundleDesc.Digest.String())
		envelopeJSON, err := attestation.UnwrapBundle(bundleJSON)
		Expect(err).NotTo(HaveOccurred())

		signed, err := attestation.HasSignatures(envelopeJSON)
		Expect(err).NotTo(HaveOccurred())
		Expect(signed).To(BeTrue(), "vex dsse envelope must be signed")

		verifiers, err := attestation.LoadVerifiers([]string{signKeys.PubKeyPath})
		Expect(err).NotTo(HaveOccurred())
		stmtBytes, err := attestation.VerifyDSSE(ctx, envelopeJSON, attestation.InTotoMediaType, verifiers)
		Expect(err).NotTo(HaveOccurred(), "DSSE signature must verify with the signing public key")
		Expect(string(stmtBytes)).To(ContainSubstring(`"predicateType":"https://openvex.dev/ns"`))
		Expect(string(stmtBytes)).To(ContainSubstring(digest[len("sha256:"):]))

		By("US5: attest verify succeeds with the right key and fails with a wrong one")
		verifyOut = werfProject.AttestVerify(ctx, &werf.AttestVerifyOptions{
			CommonOptions: werf.CommonOptions{
				ExtraArgs: []string{
					"--type", "openvex",
					"--key", signKeys.PubKeyPath,
					"--repo", repo,
					"--digest", digest,
				},
			},
		})
		Expect(verifyOut).To(ContainSubstring("CVE-2024-E2E001"))

		werfProject.AttestVerify(ctx, &werf.AttestVerifyOptions{
			CommonOptions: werf.CommonOptions{
				ShouldFail: true,
				ExtraArgs: []string{
					"--type", "openvex",
					"--key", otherKeys.PubKeyPath,
					"--repo", repo,
					"--digest", digest,
				},
			},
		})

		By("US4: rebuilding unchanged with the same key hits the cache")
		rebuildOut := werfProject.Build(ctx, &werf.BuildOptions{CommonOptions: werf.CommonOptions{Envs: signEnv}})
		Expect(rebuildOut).To(ContainSubstring("VEX artifact is up to date"))

		By("US4: rotating the key republishes the artifact")
		rotateEnv := []string{
			"WERF_SIGN_KEY=" + otherKeys.KeyPath,
			"WERF_SIGN_CERT=" + otherKeys.CertPath,
		}
		rotateOut := werfProject.Build(ctx, &werf.BuildOptions{CommonOptions: werf.CommonOptions{Envs: rotateEnv}})
		Expect(rotateOut).To(ContainSubstring("Published VEX artifact"))

		By("US4: removing the key downgrades to the unsigned artifact superseding the bundle")
		downgradeOut := werfProject.Build(ctx, &werf.BuildOptions{})
		Expect(downgradeOut).To(ContainSubstring("Published VEX artifact"))

		Expect(findVexArtifactDescriptor(ctx, repo, digest, attestation.BundleMediaType)).To(BeNil(),
			"stale signed bundle must be superseded by the unsigned artifact after key removal")
		Expect(findVexArtifactDescriptor(ctx, repo, digest, vex.DSSEMediaType)).NotTo(BeNil())

		getOut := werfProject.AttestGet(ctx, &werf.AttestGetOptions{
			CommonOptions: werf.CommonOptions{
				ExtraArgs: []string{
					"--type", "openvex",
					"--repo", repo,
					"--digest", digest,
				},
			},
		})
		Expect(getOut).To(ContainSubstring("CVE-2024-E2E001"))
	})

	It("US1: multi-platform build publishes one signed VEX bundle at the index digest", func(ctx SpecContext) {
		setupVexEnv("vanilla-docker")

		repoDirname := "repo_vex_signing_multiplatform"
		SuiteData.InitTestRepo(ctx, repoDirname, "multiplatform")
		testRepoPath := SuiteData.GetTestRepoPath(repoDirname)

		werfProject := werf.NewProject(SuiteData.WerfBinPath, testRepoPath)
		repo := suite_init.TestRepo(SuiteData.ProjectName)

		signKeys := generateVexSigningKeyPairWithCert(SuiteData.TmpDir)
		signEnv := []string{
			"WERF_SIGN_KEY=" + signKeys.KeyPath,
			"WERF_SIGN_CERT=" + signKeys.CertPath,
		}

		buildReportPath := filepath.Join(SuiteData.TmpDir, "vex_signing_multiplatform.json")
		werfProject.Build(ctx, &werf.BuildOptions{
			CommonOptions: werf.CommonOptions{
				Envs:      signEnv,
				ExtraArgs: []string{"--save-build-report", "--build-report-path", buildReportPath},
			},
		})
		indexDigest := readDigestFromReport(buildReportPath, "app")

		By("the signed bundle is attached to the index digest")
		bundleDesc := findVexArtifactDescriptor(ctx, repo, indexDigest, attestation.BundleMediaType)
		Expect(bundleDesc).NotTo(BeNil(), "signed multi-platform build must publish the VEX bundle at the index digest")
		Expect(bundleDesc.Annotations[artifact.PredicateTypeAnnotation]).To(Equal(vex.VEXPredicateURIUnversioned))

		bundleJSON := fetchVexArtifactLayerContent(ctx, repo, bundleDesc.Digest.String())
		envelopeJSON, err := attestation.UnwrapBundle(bundleJSON)
		Expect(err).NotTo(HaveOccurred())
		verifiers, err := attestation.LoadVerifiers([]string{signKeys.PubKeyPath})
		Expect(err).NotTo(HaveOccurred())
		stmtBytes, err := attestation.VerifyDSSE(ctx, envelopeJSON, attestation.InTotoMediaType, verifiers)
		Expect(err).NotTo(HaveOccurred())
		Expect(string(stmtBytes)).To(ContainSubstring(indexDigest[len("sha256:"):]))

		By("no VEX artifact is attached to any platform manifest digest")
		platforms, err := artifact.ListIndexPlatforms(ctx, repo, indexDigest)
		Expect(err).NotTo(HaveOccurred())
		Expect(platforms).To(HaveLen(2))
		for _, platform := range platforms {
			Expect(findVexArtifactDescriptor(ctx, repo, platform.Digest, attestation.BundleMediaType)).To(BeNil(),
				"platform %s must not carry a VEX bundle", platform.Platform)
			Expect(findVexArtifactDescriptor(ctx, repo, platform.Digest, vex.DSSEMediaType)).To(BeNil(),
				"platform %s must not carry a VEX artifact", platform.Platform)
		}

		By("attest verify on the index reference works without --platform")
		verifyOut := werfProject.AttestVerify(ctx, &werf.AttestVerifyOptions{
			CommonOptions: werf.CommonOptions{
				ExtraArgs: []string{
					"--type", "openvex",
					"--key", signKeys.PubKeyPath,
					"--repo", repo,
					"--digest", indexDigest,
				},
			},
		})
		Expect(verifyOut).To(ContainSubstring("CVE-2024-E2E101"))

		By("attest verify rejects --platform for the openvex type on an index reference")
		rejectOut := werfProject.AttestVerify(ctx, &werf.AttestVerifyOptions{
			CommonOptions: werf.CommonOptions{
				ShouldFail: true,
				ExtraArgs: []string{
					"--type", "openvex",
					"--key", signKeys.PubKeyPath,
					"--repo", repo,
					"--digest", indexDigest,
					"--platform", "linux/amd64",
				},
			},
		})
		Expect(rejectOut).To(ContainSubstring("--platform is not applicable"))

		By("rebuilding unchanged hits the VEX cache")
		rebuildOut := werfProject.Build(ctx, &werf.BuildOptions{CommonOptions: werf.CommonOptions{Envs: signEnv}})
		Expect(rebuildOut).To(ContainSubstring("VEX artifact is up to date"))
	})
})

type vexSigningKeyPair struct {
	KeyPath    string
	PubKeyPath string
	CertPath   string
}

func generateVexSigningKeyPairWithCert(dir string) vexSigningKeyPair {
	certs := cert_utils.GenerateCertificatesWithOptions(cert_utils.GenerateCertificatesOptions{
		KeyType:  cert_utils.KeyType_ED25519,
		PassFunc: cryptoutils.SkipPassword,
		TmpDir:   dir,
	})

	pubKeyPath := cert_utils.FormatPublicKeyToPEMFile(dir, certs.PrivKey.Public())

	return vexSigningKeyPair{KeyPath: certs.PrivRef, PubKeyPath: pubKeyPath, CertPath: certs.LeafRef}
}

func findVexArtifactDescriptor(ctx SpecContext, repo, parentDigest, artifactType string) *v1.Descriptor {
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
		if desc.ArtifactType == artifactType {
			found := desc
			return &found
		}
	}
	return nil
}

func fetchVexArtifactLayerContent(ctx SpecContext, repo, digest string) []byte {
	imgRef, err := name.NewDigest(repo+"@"+digest, name.Insecure)
	ExpectWithOffset(1, err).NotTo(HaveOccurred())

	ropts := []remote.Option{remote.WithContext(ctx), remote.WithAuth(authn.Anonymous)}

	img, err := remote.Image(imgRef, ropts...)
	ExpectWithOffset(1, err).NotTo(HaveOccurred())

	layers, err := img.Layers()
	ExpectWithOffset(1, err).NotTo(HaveOccurred())
	ExpectWithOffset(1, layers).NotTo(BeEmpty())

	rc, err := layers[0].Compressed()
	ExpectWithOffset(1, err).NotTo(HaveOccurred())
	defer rc.Close()

	content, err := io.ReadAll(rc)
	ExpectWithOffset(1, err).NotTo(HaveOccurred())
	return content
}
