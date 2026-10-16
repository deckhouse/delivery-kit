package stage

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

	"github.com/deckhouse/delivery-kit-sdk/pkg/signver"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/secure-systems-lab/go-securesystemslib/encrypted"

	"github.com/werf/werf/v3/pkg/build/signing"
	"github.com/werf/werf/v3/pkg/config"
)

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
		options := signing.NewFilesSigningOptions(signer)
		options.Enabled = true
		return options
	}

	digestOf := func(signer *signing.Signer, paths ...string) string {
		imageConfig := &config.StapelImageBase{}
		for _, p := range paths {
			imageConfig.Sign = append(imageConfig.Sign, &config.Sign{Path: p, After: "install"})
		}
		stage := GenerateSignFilesAfterInstallStage(imageConfig, enabledOptions(signer), &BaseStageOptions{})
		Expect(stage).NotTo(BeNil())

		digest, err := stage.GetDependencies(context.Background(), nil, nil, nil, nil, nil)
		Expect(err).NotTo(HaveOccurred())
		contentDigest, err := stage.GetContentDependencies(context.Background(), nil, nil)
		Expect(err).NotTo(HaveOccurred())
		Expect(contentDigest).To(Equal(digest), "the content digest must be the same input set")
		return digest
	}

	It("keeps the digest stable for the same paths and signer and changes it with either", func() {
		signerA := newSigner("a")
		signerB := newSigner("b")

		base := digestOf(signerA, "/out/x")
		Expect(digestOf(signerA, "/out/x")).To(Equal(base))
		Expect(digestOf(signerA, "/out/y")).NotTo(Equal(base), "a different signed path must change the digest")
		Expect(digestOf(signerB, "/out/x")).NotTo(Equal(base), "a different signing certificate must change the digest")
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
