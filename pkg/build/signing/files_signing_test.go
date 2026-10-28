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
	"errors"
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
	"github.com/samber/lo"
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

func encryptedKeyPEM(key *rsa.PrivateKey) []byte {
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	Expect(err).NotTo(HaveOccurred())
	encryptedKey, err := encrypted.Encrypt(keyDER, nil)
	Expect(err).NotTo(HaveOccurred())
	return pem.EncodeToMemory(&pem.Block{Type: signver.PrivateKeyPemType, Bytes: encryptedKey})
}

func newTestSignerWithCert(ctx context.Context) (*Signer, *rsa.PrivateKey, []byte) {
	key, certPEM := newTestKeyPair()

	signer, err := NewSigner(ctx, SignerOptions{
		KeyRef:  base64.StdEncoding.EncodeToString(encryptedKeyPEM(key)),
		CertRef: base64.StdEncoding.EncodeToString(certPEM),
	})
	Expect(err).NotTo(HaveOccurred())
	return signer, key, certPEM
}

func newTestSigner(ctx context.Context) (*Signer, *rsa.PrivateKey) {
	signer, key, _ := newTestSignerWithCert(ctx)
	return signer, key
}

// batchSigner is a backend that signs batches, the shape Vault Transit has: it records
// every batch it receives and refuses to sign one digest at a time.
type batchSigner struct {
	signature.SignerVerifier

	key     *rsa.PrivateKey
	batches [][][]byte
}

var _ signver.BatchSigner = (*batchSigner)(nil)

func (s *batchSigner) PublicKey(_ ...signature.PublicKeyOption) (crypto.PublicKey, error) {
	return &s.key.PublicKey, nil
}

func (s *batchSigner) SignMessage(_ io.Reader, _ ...signature.SignOption) ([]byte, error) {
	return nil, errors.New("digest-by-digest signing must not be used with a batch backend")
}

func (s *batchSigner) SignDigests(_ context.Context, digests [][]byte) ([][]byte, error) {
	s.batches = append(s.batches, digests)
	out := make([][]byte, 0, len(digests))
	for _, d := range digests {
		sig, err := rsa.SignPKCS1v15(rand.Reader, s.key, crypto.SHA256, d)
		if err != nil {
			return nil, err
		}
		out = append(out, sig)
	}
	return out, nil
}

// shortBatchSigner drops the last signature of every batch.
type shortBatchSigner struct {
	batchSigner
}

func (s *shortBatchSigner) SignDigests(ctx context.Context, digests [][]byte) ([][]byte, error) {
	sigs, err := s.batchSigner.SignDigests(ctx, digests)
	if err != nil {
		return nil, err
	}
	return sigs[:len(sigs)-1], nil
}

// countingSource counts the reads of every content and can hand out different bytes
// on the second read of one of them.
type countingSource struct {
	contents           [][]byte
	reads              []int
	mutateOnSecondRead *int
}

var _ ContentSource = (*countingSource)(nil)

func (s *countingSource) Len() int {
	return len(s.contents)
}

func (s *countingSource) Content(_ context.Context, i int) ([]byte, error) {
	if s.reads == nil {
		s.reads = make([]int, len(s.contents))
	}
	s.reads[i]++
	if s.reads[i] == 2 && s.mutateOnSecondRead != nil && i == *s.mutateOnSecondRead {
		return []byte("changed"), nil
	}
	return s.contents[i], nil
}

var _ = Describe("SignDetachedPKCS7Batch", func() {
	It("signs every content with one request to a backend that signs batches, each signature verifying against its own content", func(ctx SpecContext) {
		key, certPEM := newTestKeyPair()
		backend := &batchSigner{key: key}
		signer := &Signer{sv: &signver.SignerVerifier{Cert: certPEM, SignerVerifier: backend}}
		contents := [][]byte{[]byte("module a"), []byte("module b"), []byte("module c")}

		ders, err := SignDetachedPKCS7Batch(ctx, Contents(contents), signer)
		Expect(err).NotTo(HaveOccurred())

		Expect(backend.batches).To(HaveLen(1), "one signing request for the whole batch")
		Expect(backend.batches[0]).To(HaveLen(len(contents)))
		Expect(ders).To(HaveLen(len(contents)))
		for i, content := range contents {
			p7, err := pkcs7.Parse(ders[i])
			Expect(err).NotTo(HaveOccurred())
			p7.Content = content
			Expect(p7.Verify()).To(Succeed(), "signature %d must verify against content %d", i, i)
			if i > 0 {
				p7.Content = contents[0]
				Expect(p7.Verify()).NotTo(Succeed(), "signature %d must not verify against another content: signatures must be paired in order", i)
			}
		}
	})

	It("falls back to signing digest by digest with a backend that cannot sign batches, producing the same shape as SignDetachedPKCS7", func(ctx SpecContext) {
		signer, _ := newTestSigner(ctx)
		contents := [][]byte{[]byte("one"), []byte("two")}

		ders, err := SignDetachedPKCS7Batch(ctx, Contents(contents), signer)
		Expect(err).NotTo(HaveOccurred())
		Expect(ders).To(HaveLen(2))
		for i, content := range contents {
			p7, err := pkcs7.Parse(ders[i])
			Expect(err).NotTo(HaveOccurred())
			p7.Content = content
			Expect(p7.Verify()).To(Succeed())
		}
	})

	It("refuses a backend that returns a different number of signatures than contents", func(ctx SpecContext) {
		key, certPEM := newTestKeyPair()
		backend := &shortBatchSigner{batchSigner: batchSigner{key: key}}
		signer := &Signer{sv: &signver.SignerVerifier{Cert: certPEM, SignerVerifier: backend}}

		_, err := SignDetachedPKCS7Batch(ctx, Contents{[]byte("x"), []byte("y")}, signer)
		Expect(err).To(MatchError(ContainSubstring("signing 2 contents produced 1 signatures")))
	})

	It("refuses a batch whose signatures the certificate does not verify, naming the content", func(ctx SpecContext) {
		key, certPEM := newTestKeyPair()
		signer := &Signer{sv: &signver.SignerVerifier{
			Cert:           certPEM,
			SignerVerifier: &badSignatureSigner{pub: &key.PublicKey},
		}}

		_, err := SignDetachedPKCS7Batch(ctx, Contents{[]byte("x"), []byte("y")}, signer)
		var contentErr *ContentError
		Expect(errors.As(err, &contentErr)).To(BeTrue(), "the caller needs the index to name the file")
		Expect(contentErr.Index).To(Equal(0))
		Expect(err).To(MatchError(ContainSubstring("does not verify the signature the key produced")))
	})

	It("reads each content twice and refuses to wrap a content that changed between the reads", func(ctx SpecContext) {
		signer, _ := newTestSigner(ctx)
		source := &countingSource{contents: [][]byte{[]byte("stable"), []byte("changes")}}

		_, err := SignDetachedPKCS7Batch(ctx, source, signer)
		Expect(err).NotTo(HaveOccurred())
		Expect(source.reads).To(Equal([]int{2, 2}), "once to digest, once to wrap; never all contents at once")

		source = &countingSource{contents: [][]byte{[]byte("stable"), []byte("changes")}, mutateOnSecondRead: lo.ToPtr(1)}
		_, err = SignDetachedPKCS7Batch(ctx, source, signer)
		var contentErr *ContentError
		Expect(errors.As(err, &contentErr)).To(BeTrue())
		Expect(contentErr.Index).To(Equal(1))
		Expect(err).To(MatchError(ContainSubstring("differs from the digest that was signed")))
	})

	It("signs nothing without making a request when there is nothing to sign", func(ctx SpecContext) {
		key, certPEM := newTestKeyPair()
		backend := &batchSigner{key: key}
		signer := &Signer{sv: &signver.SignerVerifier{Cert: certPEM, SignerVerifier: backend}}

		ders, err := SignDetachedPKCS7Batch(ctx, Contents(nil), signer)
		Expect(err).NotTo(HaveOccurred())
		Expect(ders).To(BeEmpty())
		Expect(backend.batches).To(BeEmpty())
	})
})

var _ = Describe("SignDetachedPKCS7Batch with one content", func() {
	// The content a dm-verity root hash signature covers: the hex digest, no newline.
	content := []byte("3a7bd3e2360a3d29eea436fcfb7e44c735d117c42d1c1835420b6b9942dd4f1b")

	It("produces a detached SignedData without authenticated attributes that verifies against the leaf", func(ctx SpecContext) {
		signer, key := newTestSigner(ctx)

		ders, err := SignDetachedPKCS7Batch(ctx, Contents{content}, signer)
		Expect(err).NotTo(HaveOccurred())
		der := ders[0]

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

		ders, err := SignDetachedPKCS7Batch(ctx, Contents{content}, signer)
		Expect(err).NotTo(HaveOccurred())
		der := ders[0]

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

		_, err := SignDetachedPKCS7Batch(ctx, Contents{content}, signer)
		Expect(err).To(MatchError(ContainSubstring("does not verify the signature the key produced")))
	})

	It("is accepted by openssl as a detached signature of the content", func(ctx SpecContext) {
		if _, err := exec.LookPath("openssl"); err != nil {
			Skip("openssl is not installed")
		}
		signer, _ := newTestSigner(ctx)

		ders, err := SignDetachedPKCS7Batch(ctx, Contents{content}, signer)
		Expect(err).NotTo(HaveOccurred())
		der := ders[0]

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

	It("reads the certificate of a reference exactly as the signer reports it", func(ctx SpecContext) {
		signer, _, certPEM := newTestSignerWithCert(ctx)

		certFile := filepath.Join(GinkgoT().TempDir(), "leaf.pem")
		Expect(os.WriteFile(certFile, certPEM, 0o600)).To(Succeed())

		for _, ref := range []string{base64.StdEncoding.EncodeToString(certPEM), certFile} {
			Expect(ReadCertificatePEM(ref)).To(Equal(signer.Cert()),
				"the stage digest must not depend on how the certificate was passed, nor on whether a key was configured")
		}
	})

	It("fails when the signer is not configured", func(ctx SpecContext) {
		_, err := SignDetachedPKCS7Batch(ctx, Contents{content}, &Signer{})
		Expect(err).To(MatchError(ContainSubstring("signer is not configured")))
	})
})
