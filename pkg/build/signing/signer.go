package signing

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"fmt"
	"sync"

	"github.com/deckhouse/delivery-kit-sdk/pkg/signver"
	"github.com/deckhouse/delivery-kit-sdk/pkg/signver/hashivault"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
)

type SignerOptions struct {
	KeyRef           string
	CertRef          string
	IntermediatesRef string
	Vault            VaultOptions
}

func (o SignerOptions) IsZero() bool {
	return o.KeyRef == "" || o.CertRef == ""
}

// VaultOptions configures the Vault a hashivault:// key is resolved against. Every
// field is optional: an empty one falls back to the SDK's environment lookup, so a
// signer with zero VaultOptions behaves exactly as before. Setting AuthJWT switches
// authentication to that static JWT; AuthRole and AuthPath qualify it and are
// ignored without it.
type VaultOptions struct {
	Address     string
	TransitPath string
	AuthJWT     string
	AuthRole    string
	AuthPath    string
}

func (o VaultOptions) sdkOpts() hashivault.VaultOpts {
	opts := hashivault.VaultOpts{
		Address:                 o.Address,
		TransitSecretEnginePath: o.TransitPath,
	}
	if o.AuthJWT != "" {
		opts.Auth = &hashivault.VaultAuth{JWT: &hashivault.JWTAuth{JWT: o.AuthJWT, Role: o.AuthRole, Path: o.AuthPath}}
	}
	return opts
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
		KeyRef:             opts.KeyRef,
		PassFunc:           cryptoutils.SkipPassword,
		SignerVerifierOpts: signver.SignerVerifierOpts{VaultOpts: opts.Vault.sdkOpts()},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create signer verifier: %w", err)
	}
	return &Signer{
		sv: sv,
	}, nil
}
