package signing

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"fmt"
	"io"

	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/sigstore/sigstore/pkg/signature/options"
	"github.com/smallstep/pkcs7"
)

// FilesSigningOptions carries what the sign directive needs at two different moments.
// Cert is the public identity of a signature and takes part in the stage digest, so it
// is known wherever the stage chain is built, including a command that only resolves an
// already signed image. The signer holds the private key and is nil unless one was
// configured: it is required only where a signature is actually produced.
type FilesSigningOptions struct {
	Enabled bool
	Cert    string

	signer *Signer
}

func (o FilesSigningOptions) Signer() *Signer {
	return o.signer
}

func NewFilesSigningOptions(cert string, signer *Signer) FilesSigningOptions {
	return FilesSigningOptions{Cert: cert, signer: signer}
}

// SignatureFormat identifies the on-disk signature format SignDetachedPKCS7 produces.
// It is part of the sign stage digest: bump it whenever the produced bytes change in a
// way a verifier can observe (digest or encryption algorithm, authenticated attributes,
// the embedded certificate set, the CMS profile), so the change invalidates cached sign
// stages instead of serving a signature in a stale format under the old digest.
const SignatureFormat = "detached-pkcs7-rsa-sha256-v1"

// SignDetachedPKCS7 wraps an RSASSA-PKCS1-v1_5/SHA-256 signature of content into a
// detached CMS SignedData with the leaf certificate embedded and no authenticated
// attributes: the profile systemd-keyutil writes and the kernel dm-verity signature
// check and systemd-dissect read. The signature is checked against the leaf
// certificate before it is returned, so a Vault answer that does not belong to the
// certificate stops the build here.
func SignDetachedPKCS7(ctx context.Context, content []byte, signer *Signer) ([]byte, error) {
	if signer == nil || signer.sv == nil {
		return nil, errors.New("signer is not configured")
	}

	leaf, err := parseLeafCertificate(signer.Cert())
	if err != nil {
		return nil, err
	}
	leafPub, ok := leaf.PublicKey.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("signing certificate carries a %T public key, only RSA is supported for detached PKCS#7", leaf.PublicKey)
	}

	sd, err := pkcs7.NewSignedData(content)
	if err != nil {
		return nil, fmt.Errorf("create signed data: %w", err)
	}
	sd.SetDigestAlgorithm(pkcs7.OIDDigestAlgorithmSHA256)
	// The kernel PKCS#7 parser resolves the signature algorithm from this OID alone and
	// knows only rsaEncryption there; the sha256WithRSAEncryption OID pkcs7 would infer
	// from the digest makes it reject the signature with -ENOPKG.
	sd.SetEncryptionAlgorithm(pkcs7.OIDEncryptionAlgorithmRSA)

	cs := &digestSigner{ctx: ctx, sv: signer.sv, pub: leafPub}
	if err := sd.SignWithoutAttr(leaf, cs, pkcs7.SignerInfoConfig{}); err != nil {
		return nil, fmt.Errorf("sign content: %w", err)
	}
	if len(cs.signature) == 0 {
		return nil, errors.New("signing produced no signature")
	}
	if err := rsa.VerifyPKCS1v15(leafPub, crypto.SHA256, cs.digest, cs.signature); err != nil {
		return nil, fmt.Errorf("the signing certificate does not verify the signature the key produced: %w", err)
	}

	sd.Detach()
	der, err := sd.Finish()
	if err != nil {
		return nil, fmt.Errorf("encode signed data: %w", err)
	}
	return der, nil
}

func parseLeafCertificate(pemData string) (*x509.Certificate, error) {
	certs, err := cryptoutils.UnmarshalCertificatesFromPEM([]byte(pemData))
	if err != nil {
		return nil, fmt.Errorf("parse signing certificate: %w", err)
	}
	if len(certs) == 0 {
		return nil, errors.New("signing certificate is empty")
	}
	return certs[0], nil
}

// digestSigner adapts a sigstore signer to crypto.Signer for pkcs7, which hands over
// the content digest; the signer receives it as is instead of hashing again.
type digestSigner struct {
	ctx context.Context
	sv  signature.Signer
	pub crypto.PublicKey

	digest    []byte
	signature []byte
}

var _ crypto.Signer = (*digestSigner)(nil)

func (s *digestSigner) Public() crypto.PublicKey {
	return s.pub
}

func (s *digestSigner) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	if opts == nil || opts.HashFunc() != crypto.SHA256 {
		return nil, fmt.Errorf("unsupported digest for detached PKCS#7: %v", opts)
	}
	sig, err := s.sv.SignMessage(bytes.NewReader(nil),
		options.WithContext(s.ctx),
		options.WithDigest(digest),
		options.WithCryptoSignerOpts(crypto.SHA256),
	)
	if err != nil {
		return nil, fmt.Errorf("sign digest with the files signing key: %w", err)
	}
	s.digest = digest
	s.signature = sig
	return sig, nil
}
