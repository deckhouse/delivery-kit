package stage

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/deckhouse/delivery-kit-sdk/pkg/signver"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/secure-systems-lab/go-securesystemslib/encrypted"
	"github.com/smallstep/pkcs7"

	"github.com/werf/common-go/pkg/util"
	"github.com/werf/werf/v3/pkg/build/signing"
	"github.com/werf/werf/v3/pkg/config"
	"github.com/werf/werf/v3/pkg/container_backend"
	"github.com/werf/werf/v3/pkg/image"
)

type signFilesContainerBackendStub struct {
	*ContainerBackendStub

	contentByTargetPlatform map[string][]byte
}

var _ container_backend.ContainerBackend = (*signFilesContainerBackendStub)(nil)

func (backend *signFilesContainerBackendStub) ReadFileFromImage(_ context.Context, _, filePath string, opts container_backend.ReadFileFromImageOpts) ([]byte, error) {
	content, found := backend.contentByTargetPlatform[opts.TargetPlatform]
	if !found {
		return nil, fmt.Errorf("read %s: no image built for platform %q", filePath, opts.TargetPlatform)
	}
	return content, nil
}

var _ = Describe("SignFilesStage", func() {
	newSigner := func(cn string) *signing.Signer {
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		Expect(err).NotTo(HaveOccurred())
		template := &x509.Certificate{
			SerialNumber: big.NewInt(1),
			Subject:      pkix.Name{CommonName: cn},
			NotBefore:    time.Now().Add(-time.Hour),
			NotAfter:     time.Now().Add(time.Hour),
			KeyUsage:     x509.KeyUsageDigitalSignature,
		}
		certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
		Expect(err).NotTo(HaveOccurred())
		keyDER, err := x509.MarshalPKCS8PrivateKey(key)
		Expect(err).NotTo(HaveOccurred())
		encryptedKey, err := encrypted.Encrypt(keyDER, nil)
		Expect(err).NotTo(HaveOccurred())

		signer, err := signing.NewSigner(context.Background(), signing.SignerOptions{
			KeyRef:  base64.StdEncoding.EncodeToString(pem.EncodeToMemory(&pem.Block{Type: signver.PrivateKeyPemType, Bytes: encryptedKey})),
			CertRef: base64.StdEncoding.EncodeToString(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})),
		})
		Expect(err).NotTo(HaveOccurred())
		return signer
	}

	enabledOptions := func(signer *signing.Signer) signing.FilesSigningOptions {
		options := signing.NewFilesSigningOptions(signer.Cert(), signer)
		options.Enabled = true
		return options
	}

	digestOfOptions := func(options signing.FilesSigningOptions, paths ...string) string {
		imageConfig := &config.StapelImageBase{}
		for _, p := range paths {
			imageConfig.Sign = append(imageConfig.Sign, &config.Sign{Path: p, After: "install"})
		}
		stage := GenerateSignFilesAfterInstallStage(imageConfig, options, &BaseStageOptions{})
		Expect(stage).NotTo(BeNil())

		digest, err := stage.GetDependencies(context.Background(), nil, nil, nil, nil, nil)
		Expect(err).NotTo(HaveOccurred())
		contentDigest, err := stage.GetContentDependencies(context.Background(), nil, nil)
		Expect(err).NotTo(HaveOccurred())
		Expect(contentDigest).To(Equal(digest), "the content digest must be the same input set")
		return digest
	}

	digestOf := func(signer *signing.Signer, paths ...string) string {
		return digestOfOptions(enabledOptions(signer), paths...)
	}

	It("keeps the digest stable for the same paths and signer and changes it with either", func() {
		signerA := newSigner("a")
		signerB := newSigner("b")

		base := digestOf(signerA, "/out/x")
		Expect(digestOf(signerA, "/out/x")).To(Equal(base))
		Expect(digestOf(signerA, "/out/y")).NotTo(Equal(base), "a different signed path must change the digest")
		Expect(digestOf(signerB, "/out/x")).NotTo(Equal(base), "a different signing certificate must change the digest")
	})

	It("binds the digest to the signature format, so a format change invalidates the cache", func() {
		signer := newSigner("a")

		imageConfig := &config.StapelImageBase{Sign: []*config.Sign{{Path: "/out/x", After: "install"}}}
		stage := GenerateSignFilesAfterInstallStage(imageConfig, enabledOptions(signer), &BaseStageOptions{})
		expected := util.Sha256Hash(string(stage.Name()), "Format", signing.SignatureFormat, "Path", "/out/x", "Cert", signer.Cert())

		Expect(digestOf(signer, "/out/x")).To(Equal(expected), "the signature format must take part in the digest")
	})

	It("identifies the stage by the certificate alone, so no private key is needed to resolve it", func() {
		signer := newSigner("a")

		withoutKey := signing.NewFilesSigningOptions(signer.Cert(), nil)
		withoutKey.Enabled = true

		Expect(digestOfOptions(withoutKey, "/out/x")).To(Equal(digestOf(signer, "/out/x")))
	})

	It("keeps the signature of every platform in its own directory, so a concurrent platform build cannot replace a signature waiting for its container", func(ctx SpecContext) {
		const signedPath = "/out/ext.roothash"

		contentByTargetPlatform := map[string][]byte{
			"linux/amd64": []byte("amd64 root hash"),
			"linux/arm64": []byte("arm64 root hash"),
		}
		backend := &signFilesContainerBackendStub{
			ContainerBackendStub:    NewContainerBackendStub(),
			contentByTargetPlatform: contentByTargetPlatform,
		}
		conveyor := NewConveyorStub(NewGiterminismManagerStub(NewLocalGitRepoStub("9d8059842b6fde712c58315ca0ab4713d90761c0"), NewGiterminismInspectorStub()), nil, nil)
		imageConfig := &config.StapelImageBase{Name: "sysext", Sign: []*config.Sign{{Path: signedPath}}}
		imageTmpDir := filepath.Join(GinkgoT().TempDir(), "image", imageConfig.Name)
		options := enabledOptions(newSigner("a"))

		prepare := func(targetPlatform string) string {
			stage := GenerateSignFilesStage(imageConfig, options, &BaseStageOptions{
				TargetPlatform:   targetPlatform,
				ImageName:        imageConfig.Name,
				ImageTmpDir:      imageTmpDir,
				ContainerWerfDir: "/.werf",
			})
			Expect(stage).NotTo(BeNil())

			prevBuiltImage := container_backend.NewLegacyStageImage(nil, "previous-"+targetPlatform, backend, targetPlatform)
			prevBuiltImage.SetStageDesc(&image.StageDesc{Info: &image.Info{}})
			stageImage := NewStageImage(backend, prevBuiltImage.Name(), container_backend.NewLegacyStageImage(prevBuiltImage, "result-"+targetPlatform, backend, targetPlatform))

			Expect(stage.PrepareImage(ctx, conveyor, backend, &StageImage{Image: prevBuiltImage}, stageImage, nil)).To(Succeed())

			runOptions := stageImage.Builder.LegacyStapelStageBuilder().Container().RunOptions().(*container_backend.LegacyStageImageContainerOptions)
			var signaturesDirs []string
			for _, volume := range runOptions.Volume {
				hostPath, containerPath, _ := strings.Cut(volume, ":")
				if strings.HasPrefix(containerPath, "/.werf/sign/") {
					signaturesDirs = append(signaturesDirs, hostPath)
				}
			}
			Expect(signaturesDirs).To(HaveLen(1), "the stage must mount exactly one signatures directory")

			return filepath.Join(signaturesDirs[0], "0", path.Base(signedPath)+".p7s")
		}

		verifies := func(signaturePath string, content []byte) error {
			der, err := os.ReadFile(signaturePath)
			if err != nil {
				return err
			}
			p7, err := pkcs7.Parse(der)
			if err != nil {
				return err
			}
			p7.Content = content
			return p7.Verify()
		}

		amd64Signature := prepare("linux/amd64")
		Expect(verifies(amd64Signature, contentByTargetPlatform["linux/amd64"])).To(Succeed())

		arm64Signature := prepare("linux/arm64")
		Expect(verifies(arm64Signature, contentByTargetPlatform["linux/arm64"])).To(Succeed())
		Expect(verifies(amd64Signature, contentByTargetPlatform["linux/amd64"])).To(Succeed(),
			"preparing another platform must not overwrite the signature the first platform still has to install")
	})

	It("is generated only for the position the directive names and only when enabled", func() {
		imageConfig := &config.StapelImageBase{Sign: []*config.Sign{{Path: "/out/x", Before: "install"}}}
		options := enabledOptions(newSigner("a"))

		Expect(GenerateSignFilesAfterInstallStage(imageConfig, options, &BaseStageOptions{})).To(BeNil())
		Expect(GenerateSignFilesBeforeInstallStage(imageConfig, options, &BaseStageOptions{})).NotTo(BeNil())

		options.Enabled = false
		Expect(GenerateSignFilesBeforeInstallStage(imageConfig, options, &BaseStageOptions{})).To(BeNil())
	})
})
