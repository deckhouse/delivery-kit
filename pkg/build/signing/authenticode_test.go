package signing

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"io"
	"os"

	"github.com/deckhouse/delivery-kit-sdk/pkg/signver"
	"github.com/foxboron/go-uefi/authenticode"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/sigstore/sigstore/pkg/signature"
)

var _ = Describe("SignAuthenticode", func() {
	var unsignedPE []byte

	BeforeEach(func() {
		var err error
		unsignedPE, err = os.ReadFile("testdata/minimal.efi")
		Expect(err).NotTo(HaveOccurred())
	})

	It("embeds a signature the leaf certificate verifies, over the Authenticode digest of the PE", func(ctx SpecContext) {
		signer, _, certPEM := newTestSignerWithCert(ctx)

		signedPE, err := SignAuthenticode(ctx, unsignedPE, signer)
		Expect(err).NotTo(HaveOccurred())
		Expect(len(signedPE)).To(BeNumerically(">", len(unsignedPE)), "the signature is embedded in the file")

		bin, err := authenticode.Parse(bytes.NewReader(signedPE))
		Expect(err).NotTo(HaveOccurred())
		ok, err := bin.Verify(parseCert(certPEM))
		Expect(err).NotTo(HaveOccurred())
		Expect(ok).To(BeTrue())

		unsigned, err := authenticode.Parse(bytes.NewReader(unsignedPE))
		Expect(err).NotTo(HaveOccurred())
		Expect(bin.Hash(crypto.SHA256)).To(Equal(unsigned.Hash(crypto.SHA256)), "the Authenticode digest excludes the certificate table, so signing does not change it")
	})

	It("asks the signing backend for exactly one PKCS#1 v1.5 signature over a SHA-256 digest", func(ctx SpecContext) {
		key, certPEM := newTestKeyPair()
		backend := &recordingSigner{key: key}
		signer := &Signer{sv: &signver.SignerVerifier{Cert: certPEM, SignerVerifier: backend}}

		_, err := SignAuthenticode(ctx, unsignedPE, signer)
		Expect(err).NotTo(HaveOccurred())
		Expect(backend.digests).To(HaveLen(1), "one UKI, one Transit request")
		Expect(backend.digests[0]).To(HaveLen(sha256.Size))
	})

	It("rejects a signature the leaf does not verify, before embedding it or after", func(ctx SpecContext) {
		key, certPEM := newTestKeyPair()
		backend := &recordingSigner{key: key, corrupt: true}
		signer := &Signer{sv: &signver.SignerVerifier{Cert: certPEM, SignerVerifier: backend}}

		// Two gates refuse it: the raw signature is checked against the leaf's key before
		// the library embeds it, and the embedded signature is verified afterwards. Either
		// alone is enough; the error names whichever caught it.
		_, err := SignAuthenticode(ctx, unsignedPE, signer)
		Expect(err).To(Or(
			MatchError(ContainSubstring("does not verify with the leaf certificate")),
			MatchError(ContainSubstring("verify the embedded signature")),
		))
	})

	It("refuses a PE binary that already carries a signature instead of appending another", func(ctx SpecContext) {
		signer, _, _ := newTestSignerWithCert(ctx)
		signedPE, err := SignAuthenticode(ctx, unsignedPE, signer)
		Expect(err).NotTo(HaveOccurred())

		_, err = SignAuthenticode(ctx, signedPE, signer)
		Expect(err).To(MatchError(ContainSubstring("already carries 1 Authenticode signature")))
	})

	It("refuses content that is not a PE binary", func(ctx SpecContext) {
		signer, _ := newTestSigner(ctx)

		_, err := SignAuthenticode(ctx, []byte("not a PE"), signer)
		Expect(err).To(MatchError(ContainSubstring("parse PE")))
	})

	It("refuses a signer without a certificate", func(ctx SpecContext) {
		_, err := SignAuthenticode(ctx, unsignedPE, &Signer{})
		Expect(err).To(MatchError(ContainSubstring("certificate")))
	})
})

// recordingSigner is a backend that only ever sees digests, the shape Vault Transit
// has, and records them. With corrupt set it returns a signature over another digest.
type recordingSigner struct {
	signature.SignerVerifier

	key     *rsa.PrivateKey
	corrupt bool
	digests [][]byte
}

func (s *recordingSigner) PublicKey(_ ...signature.PublicKeyOption) (crypto.PublicKey, error) {
	return &s.key.PublicKey, nil
}

func (s *recordingSigner) SignMessage(_ io.Reader, opts ...signature.SignOption) ([]byte, error) {
	var digest []byte
	for _, opt := range opts {
		opt.ApplyDigest(&digest)
	}
	s.digests = append(s.digests, digest)
	if s.corrupt {
		other := sha256.Sum256([]byte("another content"))
		digest = other[:]
	}
	return rsa.SignPKCS1v15(nil, s.key, crypto.SHA256, digest)
}

func parseCert(certPEM []byte) *x509.Certificate {
	GinkgoHelper()
	block, _ := pem.Decode(certPEM)
	Expect(block).NotTo(BeNil())
	cert, err := x509.ParseCertificate(block.Bytes)
	Expect(err).NotTo(HaveOccurred())
	return cert
}
