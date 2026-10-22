package signing

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"io"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/deckhouse/delivery-kit-sdk/pkg/signver"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/secure-systems-lab/go-securesystemslib/encrypted"
	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/smallstep/pkcs7"
)

func TestFilesSigning(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Files signing suite")
}

// badSignatureSigner answers every signing request with bytes that are not a valid
// signature of the digest, the shape a wrong Vault key or a mismatched certificate
// produces.
type badSignatureSigner struct {
	signature.SignerVerifier

	pub crypto.PublicKey
}

var _ signature.SignerVerifier = (*badSignatureSigner)(nil)

func (s *badSignatureSigner) PublicKey(_ ...signature.PublicKeyOption) (crypto.PublicKey, error) {
	return s.pub, nil
}

func (s *badSignatureSigner) SignMessage(_ io.Reader, _ ...signature.SignOption) ([]byte, error) {
	return bytes.Repeat([]byte{0x42}, 256), nil
}

func newTestKeyPair() (*rsa.PrivateKey, []byte) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	Expect(err).NotTo(HaveOccurred())

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "files-signing-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	Expect(err).NotTo(HaveOccurred())

	return key, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
}

func newTestSigner(ctx context.Context) (*Signer, *rsa.PrivateKey) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	Expect(err).NotTo(HaveOccurred())

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "files-signing-test"},
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
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: signver.PrivateKeyPemType, Bytes: encryptedKey})
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	signer, err := NewSigner(ctx, SignerOptions{
		KeyRef:  base64.StdEncoding.EncodeToString(keyPEM),
		CertRef: base64.StdEncoding.EncodeToString(certPEM),
	})
	Expect(err).NotTo(HaveOccurred())
	return signer, key
}

var _ = Describe("SignDetachedPKCS7", func() {
	// The content a dm-verity root hash signature covers: the hex digest, no newline.
	content := []byte("3a7bd3e2360a3d29eea436fcfb7e44c735d117c42d1c1835420b6b9942dd4f1b")

	It("produces a detached SignedData without authenticated attributes that verifies against the leaf", func(ctx SpecContext) {
		signer, key := newTestSigner(ctx)

		der, err := SignDetachedPKCS7(ctx, content, signer)
		Expect(err).NotTo(HaveOccurred())

		p7, err := pkcs7.Parse(der)
		Expect(err).NotTo(HaveOccurred())
		Expect(p7.Content).To(BeEmpty(), "signature must be detached")
		Expect(p7.Certificates).To(HaveLen(1), "the leaf certificate must be embedded")
		Expect(p7.Signers).To(HaveLen(1))
		Expect(p7.Signers[0].AuthenticatedAttributes).To(BeEmpty(), "systemd-keyutil profile carries no authenticated attributes")
		Expect(p7.Certificates[0].PublicKey).To(Equal(&key.PublicKey))

		digest := sha256.Sum256(content)
		Expect(rsa.VerifyPKCS1v15(&key.PublicKey, crypto.SHA256, digest[:], p7.Signers[0].EncryptedDigest)).To(Succeed(),
			"the embedded signature must be PKCS#1 v1.5 over sha256(content), the form the kernel checks")

		p7.Content = content
		Expect(p7.Verify()).To(Succeed())
	})

	It("names the signature algorithm rsaEncryption, the only one the kernel parser resolves", func(ctx SpecContext) {
		signer, _ := newTestSigner(ctx)

		der, err := SignDetachedPKCS7(ctx, content, signer)
		Expect(err).NotTo(HaveOccurred())

		p7, err := pkcs7.Parse(der)
		Expect(err).NotTo(HaveOccurred())
		Expect(p7.Signers[0].DigestAlgorithm.Algorithm).To(Equal(pkcs7.OIDDigestAlgorithmSHA256))
		Expect(p7.Signers[0].DigestEncryptionAlgorithm.Algorithm).To(Equal(pkcs7.OIDEncryptionAlgorithmRSA),
			"the kernel pkcs7 parser answers -ENOPKG for sha256WithRSAEncryption (1.2.840.113549.1.1.11)")
	})

	It("refuses a signature the signing certificate does not verify", func(ctx SpecContext) {
		key, certPEM := newTestKeyPair()
		signer := &Signer{sv: &signver.SignerVerifier{
			Cert:           certPEM,
			SignerVerifier: &badSignatureSigner{pub: &key.PublicKey},
		}}

		_, err := SignDetachedPKCS7(ctx, content, signer)
		Expect(err).To(MatchError(ContainSubstring("does not verify the signature the key produced")))
	})

	It("is accepted by openssl as a detached signature of the content", func(ctx SpecContext) {
		if _, err := exec.LookPath("openssl"); err != nil {
			Skip("openssl is not installed")
		}
		signer, _ := newTestSigner(ctx)

		der, err := SignDetachedPKCS7(ctx, content, signer)
		Expect(err).NotTo(HaveOccurred())

		dir := GinkgoT().TempDir()
		p7sPath := filepath.Join(dir, "x.roothash.p7s")
		contentPath := filepath.Join(dir, "x.roothash")
		Expect(os.WriteFile(p7sPath, der, 0o600)).To(Succeed())
		Expect(os.WriteFile(contentPath, content, 0o600)).To(Succeed())

		out, err := exec.CommandContext(ctx, "openssl", "smime", "-verify", "-inform", "der", "-in", p7sPath, "-content", contentPath, "-noverify", "-out", os.DevNull).CombinedOutput()
		Expect(err).NotTo(HaveOccurred(), string(out))

		tampered := append([]byte{}, content...)
		tampered[0] ^= 1
		Expect(os.WriteFile(contentPath, tampered, 0o600)).To(Succeed())
		_, err = exec.CommandContext(ctx, "openssl", "smime", "-verify", "-inform", "der", "-in", p7sPath, "-content", contentPath, "-noverify", "-out", os.DevNull).CombinedOutput()
		Expect(err).To(HaveOccurred(), "openssl must reject the signature over different content")
	})

	It("fails when the signer is not configured", func(ctx SpecContext) {
		_, err := SignDetachedPKCS7(ctx, content, &Signer{})
		Expect(err).To(MatchError(ContainSubstring("signer is not configured")))
	})
})
