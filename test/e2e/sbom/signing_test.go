package e2e_build_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/secure-systems-lab/go-securesystemslib/encrypted"

	"github.com/werf/werf/v2/pkg/attestation"
	"github.com/werf/werf/v2/pkg/image"
	sbomImage "github.com/werf/werf/v2/pkg/sbom/image"
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

			signKeys := generateSigningKeyPairWithCert(SuiteData.TmpDir, "sbom-signing")
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
			bundleDesc := findArtifactDescriptor(ctx, repo, digest, attestation.BundleMediaType)
			Expect(bundleDesc).NotTo(BeNil(), "no sigstore bundle artifact found in fallback index")
			Expect(bundleDesc.Annotations[image.WerfImageNameAnnotation]).To(Equal("app"))
			Expect(bundleDesc.Annotations[image.WerfChecksumAnnotation]).NotTo(BeEmpty())

			By("asserting no stale bare-DSSE artifact remains for the same image")
			dsseDesc := findArtifactDescriptor(ctx, repo, digest, attestation.DSSEMediaType)
			Expect(dsseDesc).To(BeNil(), "stale bare-DSSE artifact must be superseded by the bundle")

			By("fetching the bundle and verifying the DSSE signature with the public key")
			bundleJSON := fetchArtifactLayerContent(ctx, repo, bundleDesc.Digest.String())

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

		dsseDesc := findArtifactDescriptor(ctx, repo, digest, attestation.DSSEMediaType)
		Expect(dsseDesc).NotTo(BeNil(), "unsigned build must keep the legacy bare-DSSE artifact")

		bundleDesc := findArtifactDescriptor(ctx, repo, digest, attestation.BundleMediaType)
		Expect(bundleDesc).To(BeNil(), "unsigned build must not produce a bundle artifact")

		envelopeJSON := fetchArtifactLayerContent(ctx, repo, dsseDesc.Digest.String())
		signed, err := attestation.HasSignatures(envelopeJSON)
		Expect(err).NotTo(HaveOccurred())
		Expect(signed).To(BeFalse(), "unsigned build must produce an unsigned envelope")
	})

	It("build with key but without cert fails", Label("e2e", "sbom", "sbom-signing", "negative"), func(ctx SpecContext) {
		setupSbomBuildEnv(setupEnvOptions{ContainerBackendMode: "vanilla-docker"})

		repoDirname := "repo_sbom_signing_no_cert"
		SuiteData.InitTestRepo(ctx, repoDirname, "signing")
		testRepoPath := SuiteData.GetTestRepoPath(repoDirname)

		signKeys := generateSigningKeyPairWithCert(SuiteData.TmpDir, "sbom-no-cert")

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

type signingKeyPair struct {
	KeyPath    string
	PubKeyPath string
	CertPath   string
}

func generateSigningKeyPairWithCert(dir, suffix string) signingKeyPair {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ExpectWithOffset(1, err).NotTo(HaveOccurred())

	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	ExpectWithOffset(1, err).NotTo(HaveOccurred())
	encKeyDER, err := encrypted.Encrypt(keyDER, []byte{})
	ExpectWithOffset(1, err).NotTo(HaveOccurred())
	keyPath := filepath.Join(dir, suffix+".key")
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "ENCRYPTED DELIVERY-KIT PRIVATE KEY", Bytes: encKeyDER})
	ExpectWithOffset(1, os.WriteFile(keyPath, keyPEM, 0o600)).To(Succeed())

	pubDER, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	ExpectWithOffset(1, err).NotTo(HaveOccurred())
	pubKeyPath := filepath.Join(dir, suffix+".pub")
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})
	ExpectWithOffset(1, os.WriteFile(pubKeyPath, pubPEM, 0o644)).To(Succeed())

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "sbom-signing-e2e"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	ExpectWithOffset(1, err).NotTo(HaveOccurred())
	certPath := filepath.Join(dir, suffix+".crt")
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	ExpectWithOffset(1, os.WriteFile(certPath, certPEM, 0o644)).To(Succeed())

	return signingKeyPair{KeyPath: keyPath, PubKeyPath: pubKeyPath, CertPath: certPath}
}

func findArtifactDescriptor(ctx SpecContext, repo, parentDigest, artifactType string) *v1.Descriptor {
	tagRef, err := name.NewTag(repo+":"+sbomImage.FallbackTag(parentDigest), name.Insecure)
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

func fetchArtifactLayerContent(ctx SpecContext, repo, digest string) []byte {
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

// runCosignOfflineVerify runs the canonical offline cosign verification when a
// cosign binary is available (env WERF_TEST_COSIGN_BIN or in PATH):
//
//	cosign trusted-root create --out tr.json
//	cosign verify-attestation --new-bundle-format --trusted-root tr.json \
//	  --insecure-ignore-tlog=true --key pub.pem --type cyclonedx <image>@<digest>
func runCosignOfflineVerify(ctx SpecContext, repo, digest, pubKeyPath string) {
	cosignBin := os.Getenv("WERF_TEST_COSIGN_BIN")
	if cosignBin == "" {
		var err error
		cosignBin, err = exec.LookPath("cosign")
		if err != nil {
			Skip("cosign binary not available: set WERF_TEST_COSIGN_BIN or add cosign to PATH")
		}
	}

	trustedRootPath := filepath.Join(SuiteData.TmpDir, "cosign-trusted-root.json")
	createCmd := exec.CommandContext(ctx, cosignBin, "trusted-root", "create", "--out", trustedRootPath)
	createOut, err := createCmd.CombinedOutput()
	Expect(err).NotTo(HaveOccurred(), "cosign trusted-root create failed: %s", string(createOut))

	verifyCmd := exec.CommandContext(ctx, cosignBin, "verify-attestation",
		"--new-bundle-format",
		"--trusted-root", trustedRootPath,
		"--insecure-ignore-tlog=true",
		"--key", pubKeyPath,
		"--type", "cyclonedx",
		repo+"@"+digest,
	)
	verifyCmd.Env = append(os.Environ(), "COSIGN_ALLOW_INSECURE_REGISTRY=true")
	verifyOut, err := verifyCmd.CombinedOutput()
	Expect(err).NotTo(HaveOccurred(), "cosign verify-attestation failed: %s", string(verifyOut))
	Expect(string(verifyOut)).To(ContainSubstring("verified"))
}
