package signing

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"fmt"
	"io"

	"github.com/sigstore/sigstore/pkg/cryptoutils"
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

// SignatureFormat identifies the on-disk signature format SignDetachedPKCS7Batch produces.
// It is part of the sign stage digest: bump it whenever the produced bytes change in a
// way a verifier can observe (digest or encryption algorithm, authenticated attributes,
// the embedded certificate set, the CMS profile), so the change invalidates cached sign
// stages instead of serving a signature in a stale format under the old digest.
const SignatureFormat = "detached-pkcs7-rsa-sha256-v1"

// ContentSource hands out the contents of a batch one at a time, so that a batch of
// hundreds of files never has to be in memory at once. Content is asked for twice per
// index: once to digest it, once to wrap its signature.
type ContentSource interface {
	Len() int
	Content(ctx context.Context, i int) ([]byte, error)
}

// Contents is a ContentSource over contents already in memory.
type Contents [][]byte

var _ ContentSource = Contents(nil)

func (c Contents) Len() int {
	return len(c)
}

func (c Contents) Content(_ context.Context, i int) ([]byte, error) {
	return c[i], nil
}

// ContentError names the content of a batch a failure belongs to.
type ContentError struct {
	Index int
	Err   error
}

func (e *ContentError) Error() string {
	return fmt.Sprintf("content %d: %v", e.Index, e.Err)
}

func (e *ContentError) Unwrap() error {
	return e.Err
}

// SignDetachedPKCS7Batch wraps an RSASSA-PKCS1-v1_5/SHA-256 signature of every content
// into a detached CMS SignedData with the leaf certificate embedded and no
// authenticated attributes: the profile systemd-keyutil writes and the kernel
// dm-verity signature check and systemd-dissect read. The contents are signed through
// one SignDigests call: a signing stage can carry hundreds of files, and with Vault
// Transit a request per file is what a rate limit in front of it stops. Each
// signature is checked against the leaf certificate before it is wrapped, so a Vault
// answer that does not belong to the certificate stops the build here. The signatures
// are returned in content order; a failure while digesting, verifying or wrapping one
// content is a *ContentError.
func SignDetachedPKCS7Batch(ctx context.Context, contents ContentSource, signer *Signer) ([][]byte, error) {
	if signer == nil || signer.sv == nil {
		return nil, errors.New("signer is not configured")
	}
	n := contents.Len()
	if n == 0 {
		return nil, nil
	}

	leaf, err := parseLeafCertificate(signer.Cert())
	if err != nil {
		return nil, err
	}
	leafPub, ok := leaf.PublicKey.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("signing certificate carries a %T public key, only RSA is supported for detached PKCS#7", leaf.PublicKey)
	}

	digests := make([][]byte, 0, n)
	for i := 0; i < n; i++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		content, err := contents.Content(ctx, i)
		if err != nil {
			return nil, &ContentError{Index: i, Err: err}
		}
		sum := sha256.Sum256(content)
		digests = append(digests, sum[:])
	}

	signatures, err := signer.sv.SignDigests(ctx, digests)
	if err != nil {
		return nil, fmt.Errorf("sign %d digests with the files signing key: %w", len(digests), err)
	}
	if len(signatures) != n {
		return nil, fmt.Errorf("signing %d contents produced %d signatures", n, len(signatures))
	}

	ders := make([][]byte, 0, n)
	for i := 0; i < n; i++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if len(signatures[i]) == 0 {
			return nil, &ContentError{Index: i, Err: errors.New("signing produced no signature")}
		}
		if err := rsa.VerifyPKCS1v15(leafPub, crypto.SHA256, digests[i], signatures[i]); err != nil {
			return nil, &ContentError{Index: i, Err: fmt.Errorf("the signing certificate does not verify the signature the key produced: %w", err)}
		}

		content, err := contents.Content(ctx, i)
		if err != nil {
			return nil, &ContentError{Index: i, Err: err}
		}
		// A content that changed between the two reads would be wrapped with a
		// signature of other bytes: precomputedSigner refuses a digest other than the
		// one that was signed.
		der, err := wrapDetachedPKCS7(content, digests[i], signatures[i], leaf, leafPub)
		if err != nil {
			return nil, &ContentError{Index: i, Err: err}
		}
		ders = append(ders, der)
	}
	return ders, nil
}

func wrapDetachedPKCS7(content, digest, sig []byte, leaf *x509.Certificate, leafPub *rsa.PublicKey) ([]byte, error) {
	sd, err := pkcs7.NewSignedData(content)
	if err != nil {
		return nil, fmt.Errorf("create signed data: %w", err)
	}
	sd.SetDigestAlgorithm(pkcs7.OIDDigestAlgorithmSHA256)
	// The kernel PKCS#7 parser resolves the signature algorithm from this OID alone and
	// knows only rsaEncryption there; the sha256WithRSAEncryption OID pkcs7 would infer
	// from the digest makes it reject the signature with -ENOPKG.
	sd.SetEncryptionAlgorithm(pkcs7.OIDEncryptionAlgorithmRSA)

	cs := &precomputedSigner{pub: leafPub, digest: digest, signature: sig}
	if err := sd.SignWithoutAttr(leaf, cs, pkcs7.SignerInfoConfig{}); err != nil {
		return nil, fmt.Errorf("sign content: %w", err)
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

// precomputedSigner hands pkcs7 a signature obtained beforehand: pkcs7 calls Sign with
// the content digest, which has to be the one the signature was made over.
type precomputedSigner struct {
	pub       crypto.PublicKey
	digest    []byte
	signature []byte
}

var _ crypto.Signer = (*precomputedSigner)(nil)

func (s *precomputedSigner) Public() crypto.PublicKey {
	return s.pub
}

func (s *precomputedSigner) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	if opts == nil || opts.HashFunc() != crypto.SHA256 {
		return nil, fmt.Errorf("unsupported digest for detached PKCS#7: %v", opts)
	}
	if !bytes.Equal(digest, s.digest) {
		return nil, errors.New("pkcs7 digest differs from the digest that was signed")
	}
	return s.signature, nil
}
