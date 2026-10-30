package signing

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rsa"
	"errors"
	"fmt"
	"io"

	"github.com/foxboron/go-uefi/authenticode"
	"github.com/sigstore/sigstore/pkg/signature/options"
)

// AuthenticodeFormat identifies the signature format SignAuthenticode produces: an
// Authenticode signature embedded in the PE certificate table, RSASSA-PKCS1-v1_5 over
// SHA-256, with the leaf certificate and no timestamp.
const AuthenticodeFormat = "authenticode-rsa-sha256-v1"

// SignAuthenticode returns the PE binary with an Authenticode signature embedded, the
// form UEFI firmware checks against its db at boot: the Authenticode digest of the
// image — the file without its checksum and certificate table — wrapped in
// SpcIndirectDataContent and signed as CMS SignedData with authenticated attributes.
// The signing backend sees only the SHA-256 digest of those attributes, the one request
// Vault Transit needs, and the signature is checked against the leaf certificate before
// it is embedded.
func SignAuthenticode(ctx context.Context, pe []byte, signer *Signer) ([]byte, error) {
	leaf, err := parseLeafCertificate(signer.Cert())
	if err != nil {
		return nil, err
	}
	leafPub, ok := leaf.PublicKey.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("leaf certificate public key is %T; Authenticode signing here supports RSA only", leaf.PublicKey)
	}

	bin, err := authenticode.Parse(bytes.NewReader(pe))
	if err != nil {
		return nil, fmt.Errorf("parse PE: %w", err)
	}
	if signatures, err := bin.Signatures(); err == nil && len(signatures) > 0 {
		return nil, fmt.Errorf("the PE binary already carries %d Authenticode signature(s); a signed binary is not signed again", len(signatures))
	}

	if _, err := bin.Sign(&authenticodeDigestSigner{ctx: ctx, signer: signer, public: leafPub}, leaf); err != nil {
		return nil, fmt.Errorf("sign PE: %w", err)
	}

	verified, err := bin.Verify(leaf)
	if err != nil {
		return nil, fmt.Errorf("verify the embedded signature: %w", err)
	}
	if !verified {
		return nil, errors.New("the embedded signature does not verify with the leaf certificate")
	}
	return bin.Bytes(), nil
}

// authenticodeDigestSigner is the crypto.Signer the PE library signs through: it hands
// the SHA-256 digest of the signed attributes to the signing backend and checks the
// raw signature against the leaf's key before the library embeds it. A signature the
// library would compute differently — PSS, or another hash — is refused rather than
// silently produced.
type authenticodeDigestSigner struct {
	ctx    context.Context
	signer *Signer
	public *rsa.PublicKey
}

var _ crypto.Signer = (*authenticodeDigestSigner)(nil)

func (s *authenticodeDigestSigner) Public() crypto.PublicKey {
	return s.public
}

func (s *authenticodeDigestSigner) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	if _, pss := opts.(*rsa.PSSOptions); pss {
		return nil, errors.New("PE library asked for a PSS signature; the signing key signs PKCS#1 v1.5")
	}
	if opts.HashFunc() != crypto.SHA256 {
		return nil, fmt.Errorf("PE library asked for a %s signature; the signing key signs SHA-256 digests", opts.HashFunc())
	}
	if len(digest) != crypto.SHA256.Size() {
		return nil, fmt.Errorf("PE library handed a digest of %d bytes; want %d", len(digest), crypto.SHA256.Size())
	}

	sig, err := s.signer.SignerVerifier().SignMessage(nil, options.WithDigest(digest), options.WithCryptoSignerOpts(crypto.SHA256), options.WithContext(s.ctx))
	if err != nil {
		return nil, fmt.Errorf("sign digest with the files signing key: %w", err)
	}
	if err := rsa.VerifyPKCS1v15(s.public, crypto.SHA256, digest, sig); err != nil {
		return nil, fmt.Errorf("signature from the signing key does not verify with the leaf certificate: %w", err)
	}
	return sig, nil
}
