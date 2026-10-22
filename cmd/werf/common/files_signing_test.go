package common

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"math/big"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/samber/lo"

	"github.com/werf/werf/v3/pkg/config"
)

var _ = Describe("files signing options", func() {
	signingImage := func(name string) config.ImageInterface {
		return &config.StapelImage{StapelImageBase: &config.StapelImageBase{Name: name, Sign: []*config.Sign{{Path: "/out/x", After: "install"}}}}
	}

	plainImage := func(name string) config.ImageInterface {
		return &config.StapelImage{StapelImageBase: &config.StapelImageBase{Name: name}}
	}

	newConfig := func(images ...config.ImageInterface) *config.WerfConfig {
		return config.NewWerfConfig(&config.Meta{}, images)
	}

	allImages := func(werfConfig *config.WerfConfig) config.ImagesToProcess {
		imagesToProcess, err := config.NewImagesToProcess(werfConfig, nil, false, false)
		Expect(err).NotTo(HaveOccurred())
		return imagesToProcess
	}

	someImages := func(werfConfig *config.WerfConfig, names ...string) config.ImagesToProcess {
		imagesToProcess, err := config.NewImagesToProcess(werfConfig, names, false, false)
		Expect(err).NotTo(HaveOccurred())
		return imagesToProcess
	}

	certPEM := func() string {
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		Expect(err).NotTo(HaveOccurred())
		template := &x509.Certificate{
			SerialNumber: big.NewInt(1),
			Subject:      pkix.Name{CommonName: "files-signing-options-test"},
			NotBefore:    time.Now().Add(-time.Hour),
			NotAfter:     time.Now().Add(time.Hour),
			KeyUsage:     x509.KeyUsageDigitalSignature,
		}
		certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
		Expect(err).NotTo(HaveOccurred())
		return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}))
	}

	DescribeTable("refuses an incomplete command line before any stage runs",
		func(cmdData *CmdData, expectedError string) {
			werfConfig := newConfig(signingImage("app"))
			_, err := getFilesSigningOptions(context.Background(), cmdData, werfConfig, allImages(werfConfig))
			Expect(err).To(MatchError(ContainSubstring(expectedError)))
		},
		Entry("no certificate", &CmdData{}, "images app declare files to sign: specify the signing certificate"),
		Entry("certificate that cannot be read", &CmdData{SignBuildFileCert: lo.ToPtr("c")}, "read the files signing certificate"),
	)

	It("refuses a vault role or auth path that qualifies no jwt", func() {
		werfConfig := newConfig(signingImage("app"))
		cert := base64.StdEncoding.EncodeToString([]byte(certPEM()))

		for _, cmdData := range []*CmdData{
			{SignBuildFileKey: lo.ToPtr("k"), SignBuildFileCert: lo.ToPtr(cert), SignBuildFileVaultAuthRole: lo.ToPtr("r")},
			{SignBuildFileKey: lo.ToPtr("k"), SignBuildFileCert: lo.ToPtr(cert), SignBuildFileVaultAuthPath: lo.ToPtr("fox")},
		} {
			_, err := getFilesSigningOptions(context.Background(), cmdData, werfConfig, allImages(werfConfig))
			Expect(err).To(MatchError(ContainSubstring("qualify --sign-build-file-vault-auth-jwt")))
		}
	})

	It("is disabled when no image being processed declares files to sign", func() {
		werfConfig := newConfig(plainImage("app"))

		options, err := getFilesSigningOptions(context.Background(), &CmdData{}, werfConfig, allImages(werfConfig))
		Expect(err).NotTo(HaveOccurred())
		Expect(options.Enabled).To(BeFalse())
	})

	It("ignores the sign directive of an image that is not being processed", func() {
		werfConfig := newConfig(plainImage("plain"), signingImage("signed"))

		options, err := getFilesSigningOptions(context.Background(), &CmdData{}, werfConfig, someImages(werfConfig, "plain"))
		Expect(err).NotTo(HaveOccurred())
		Expect(options.Enabled).To(BeFalse(), "building an unrelated image must not demand the signing material of another one")
	})

	It("identifies the signature by the certificate without a private key", func() {
		werfConfig := newConfig(signingImage("app"))
		cert := certPEM()

		options, err := getFilesSigningOptions(context.Background(), &CmdData{
			SignBuildFileCert: lo.ToPtr(base64.StdEncoding.EncodeToString([]byte(cert))),
		}, werfConfig, allImages(werfConfig))
		Expect(err).NotTo(HaveOccurred())
		Expect(options.Enabled).To(BeTrue())
		Expect(options.Cert).To(Equal(cert))
		Expect(options.Signer()).To(BeNil(), "no private key was given, so nothing can sign")
	})
})
