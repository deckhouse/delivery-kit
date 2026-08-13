package signing

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"fmt"
	"sync"

	"github.com/deckhouse/delivery-kit-sdk/pkg/signver"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
)

type SignerOptions struct {
	KeyRef           string
	CertRef          string
	IntermediatesRef string
}

func (o SignerOptions) IsZero() bool {
	return o.KeyRef == "" || o.CertRef == ""
}

type Signer struct {
	sv *signver.SignerVerifier

	fingerprintOnce sync.Once
	fingerprint     string
}

func (s *Signer) SignerVerifier() *signver.SignerVerifier {
	return s.sv
}

// Fingerprint returns a stable cache identity of the signing public key
// (hex SHA-256 of its DER SPKI form), or an empty string when the signer is
// not configured or the key cannot be derived. The value is computed once.
func (s *Signer) Fingerprint() string {
	s.fingerprintOnce.Do(func() {
		if s.sv == nil {
			return
		}

		pub, err := s.sv.PublicKey()
		if err != nil {
			return
		}

		der, err := x509.MarshalPKIXPublicKey(pub)
		if err != nil {
			return
		}

		digest := sha256.Sum256(der)
		s.fingerprint = fmt.Sprintf("signer:%x", digest)
	})
	return s.fingerprint
}

func (s *Signer) Cert() string {
	if s.sv == nil {
		return ""
	}
	return string(s.sv.Cert)
}

func (s *Signer) Chain() string {
	if s.sv == nil {
		return ""
	}
	return string(s.sv.Chain)
}

func NewSigner(ctx context.Context, opts SignerOptions) (*Signer, error) {
	if opts.IsZero() {
		return &Signer{}, nil
	}
	sv, err := signver.NewSignerVerifier(ctx, opts.CertRef, opts.IntermediatesRef, signver.KeyOpts{
		KeyRef:   opts.KeyRef,
		PassFunc: cryptoutils.SkipPassword,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create signer verifier: %w", err)
	}
	return &Signer{
		sv: sv,
	}, nil
}
