package e2e_build_test

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	_ "embed"
	"encoding/base64"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"github.com/smallstep/pkcs7"

	elfTar "github.com/werf/werf/v3/pkg/signature/elf/tar"
	"github.com/werf/werf/v3/test/pkg/report"
	"github.com/werf/werf/v3/test/pkg/utils"
	"github.com/werf/werf/v3/test/pkg/werf"
)

const (
	signFilesContent = "3a7bd3e2360a3d29eea436fcfb7e44c735d117c42d1c1835420b6b9942dd4f1b"
	signFilesPath    = "/out/ext.roothash"
)

var (
	//go:embed _fixtures/sign_files/keys/rsa_2048.pem.key
	signFilesKeyData []byte
	//go:embed _fixtures/sign_files/keys/rsa_2048.pem.crt
	signFilesCertData []byte
)

type signFilesTestOptions struct {
	setupEnvOptions
}

var _ = Describe("sign directive", Label("e2e", "sign-files", "simple"), func() {
	signArgs := []string{
		"--sign-build-file-key", base64.StdEncoding.EncodeToString(signFilesKeyData),
		"--sign-build-file-cert", base64.StdEncoding.EncodeToString(signFilesCertData),
	}

	// readSignedFiles returns the signed file and its .p7s out of the built image.
	readSignedFiles := func(imageName string) (content, p7s []byte) {
		img := loadImageFromRegistry(imageName)
		utils.ForEachImageFile(SuiteData.TmpDir, img, func(header *elfTar.Header, tmpLocalPath string) {
			switch "/" + strings.TrimPrefix(header.Name, "/") {
			case signFilesPath:
				var err error
				content, err = os.ReadFile(tmpLocalPath)
				Expect(err).To(Succeed())
			case signFilesPath + ".p7s":
				var err error
				p7s, err = os.ReadFile(tmpLocalPath)
				Expect(err).To(Succeed())
			}
		})
		Expect(content).To(Equal([]byte(signFilesContent)))
		Expect(p7s).NotTo(BeEmpty(), "the image must carry %s.p7s", signFilesPath)
		return content, p7s
	}

	// expectSystemdProfile asserts the .p7s is what systemd-keyutil would have written:
	// a detached SignedData, no authenticated attributes, the leaf embedded, an
	// RSASSA-PKCS1-v1_5/SHA-256 signature over the content itself.
	expectSystemdProfile := func(content, p7s []byte) {
		p7, err := pkcs7.Parse(p7s)
		Expect(err).To(Succeed())
		Expect(p7.Content).To(BeEmpty())
		Expect(p7.Signers).To(HaveLen(1))
		Expect(p7.Signers[0].AuthenticatedAttributes).To(BeEmpty())

		certs, err := cryptoutils.UnmarshalCertificatesFromPEM(signFilesCertData)
		Expect(err).To(Succeed())
		Expect(p7.Certificates).To(HaveLen(1))
		Expect(p7.Certificates[0].Raw).To(Equal(certs[0].Raw))

		digest := sha256.Sum256(content)
		Expect(rsa.VerifyPKCS1v15(certs[0].PublicKey.(*rsa.PublicKey), crypto.SHA256, digest[:], p7.Signers[0].EncryptedDigest)).To(Succeed())

		if _, err := exec.LookPath("openssl"); err != nil {
			return
		}
		dir := GinkgoT().TempDir()
		contentPath := filepath.Join(dir, "ext.roothash")
		p7sPath := contentPath + ".p7s"
		Expect(os.WriteFile(contentPath, content, 0o600)).To(Succeed())
		Expect(os.WriteFile(p7sPath, p7s, 0o600)).To(Succeed())
		out, err := exec.Command("openssl", "smime", "-verify", "-inform", "der", "-in", p7sPath, "-content", contentPath, "-noverify", "-out", os.DevNull).CombinedOutput()
		Expect(err).To(Succeed(), string(out))
	}

	DescribeTable("resolves a built image by its certificate alone, without the private key",
		func(ctx SpecContext, testOpts signFilesTestOptions) {
			setupEnv(testOpts.setupEnvOptions)

			SuiteData.InitTestRepo(ctx, "repo0", "sign_files/state")
			werfProject := werf.NewProject(SuiteData.WerfBinPath, SuiteData.GetTestRepoPath("repo0"))

			By("building with key and certificate")
			werfProject.Build(ctx, &werf.BuildOptions{CommonOptions: werf.CommonOptions{ExtraArgs: signArgs}})

			By("resolving the same image with the certificate only")
			out := werfProject.Build(ctx, &werf.BuildOptions{CommonOptions: werf.CommonOptions{ExtraArgs: []string{
				"--require-built-images",
				"--sign-build-file-cert", base64.StdEncoding.EncodeToString(signFilesCertData),
			}}})
			Expect(out).To(ContainSubstring("Use previously built image for sysext"))
		},
		backendEntry("with repo using Docker", signFilesTestOptions{setupEnvOptions: setupEnvOptions{
			ContainerBackendMode: "docker",
			WithLocalRepo:        true,
		}}),
	)

	DescribeTable("signs the declared file after the named stage",
		func(ctx SpecContext, testOpts signFilesTestOptions) {
			setupEnv(testOpts.setupEnvOptions)

			SuiteData.InitTestRepo(ctx, "repo0", "sign_files/state")
			werfProject := report.NewProjectWithReport(werf.NewProject(SuiteData.WerfBinPath, SuiteData.GetTestRepoPath("repo0")))

			By("building with the files signer")
			buildOut, buildReport := werfProject.BuildWithReport(ctx, SuiteData.GetBuildReportPath("report0.json"), &werf.WithReportOptions{CommonOptions: werf.CommonOptions{ExtraArgs: signArgs}})
			Expect(buildOut).To(ContainSubstring("Building stage sysext/install"))
			Expect(buildOut).To(ContainSubstring("Signing " + signFilesPath))
			Expect(buildOut).To(ContainSubstring("Building stage sysext/signFilesAfterInstall"))
			Expect(buildOut).To(ContainSubstring("Building stage sysext/setup"))

			By("verifying the signature in the image")
			expectSystemdProfile(readSignedFiles(buildReport.Images["sysext"].DockerImageName))

			By("rebuilding with the same key reuses the stage")
			rebuildOut := werfProject.Build(ctx, &werf.BuildOptions{CommonOptions: werf.CommonOptions{ExtraArgs: signArgs}})
			Expect(rebuildOut).To(ContainSubstring("Use previously built image for sysext"))
			Expect(rebuildOut).NotTo(ContainSubstring("Building stage"))
		},
		backendEntry("with repo using Docker", signFilesTestOptions{setupEnvOptions: setupEnvOptions{
			ContainerBackendMode: "docker",
			WithLocalRepo:        true,
		}}),
		backendEntry("with repo using Native Rootless", signFilesTestOptions{setupEnvOptions: setupEnvOptions{
			ContainerBackendMode: "native-rootless",
			WithLocalRepo:        true,
		}}),
	)

	DescribeTable("keeps the build offline under build.sbom.enable and still signs",
		func(ctx SpecContext, testOpts signFilesTestOptions) {
			setupEnv(testOpts.setupEnvOptions)

			SuiteData.InitTestRepo(ctx, "repo0", "sign_files/state_sbom")
			werfProject := report.NewProjectWithReport(werf.NewProject(SuiteData.WerfBinPath, SuiteData.GetTestRepoPath("repo0")))

			buildOut, buildReport := werfProject.BuildWithReport(ctx, SuiteData.GetBuildReportPath("report0.json"), &werf.WithReportOptions{CommonOptions: werf.CommonOptions{ExtraArgs: signArgs}})
			Expect(buildOut).To(ContainSubstring("Network is disabled for shell stages"))
			Expect(buildOut).To(ContainSubstring("Building stage sysext/signFilesAfterInstall"))

			expectSystemdProfile(readSignedFiles(buildReport.Images["sysext"].DockerImageName))
		},
		backendEntry("with repo using Docker", signFilesTestOptions{setupEnvOptions: setupEnvOptions{
			ContainerBackendMode: "docker",
			WithLocalRepo:        true,
		}}),
	)

	DescribeTable("refuses to build an image whose signatures it cannot produce",
		func(ctx SpecContext, testOpts signFilesTestOptions) {
			setupEnv(testOpts.setupEnvOptions)

			SuiteData.InitTestRepo(ctx, "repo0", "sign_files/state")
			werfProject := werf.NewProject(SuiteData.WerfBinPath, SuiteData.GetTestRepoPath("repo0"))

			By("no certificate: the build stops before any stage, the signature has no identity")
			out, err := werfProject.BuildWithErr(ctx, &werf.BuildOptions{})
			Expect(err).To(HaveOccurred())
			Expect(out).To(ContainSubstring("images sysext declare files to sign"))
			Expect(out).NotTo(ContainSubstring("Building stage"))

			By("certificate without a key: the stage that must sign refuses to build")
			out, err = werfProject.BuildWithErr(ctx, &werf.BuildOptions{CommonOptions: werf.CommonOptions{ExtraArgs: []string{
				"--sign-build-file-cert", base64.StdEncoding.EncodeToString(signFilesCertData),
			}}})
			Expect(err).To(HaveOccurred())
			Expect(out).To(ContainSubstring("specify the private key with --sign-build-file-key"))
		},
		backendEntry("with repo using Docker", signFilesTestOptions{setupEnvOptions: setupEnvOptions{
			ContainerBackendMode: "docker",
			WithLocalRepo:        true,
		}}),
	)
})
