package attestation

import (
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
)

const BundleMediaType = "application/vnd.dev.sigstore.bundle.v0.3+json"

// Bundle is a minimal Sigstore Bundle v0.3 for offline key-based verification.
// Fields for transparency log entries, certificate chains, and RFC 3161
// timestamps are intentionally omitted: they are not needed when the verifier
// holds the public key directly and the bundle is verified with
// --insecure-ignore-tlog.
type Bundle struct {
	MediaType            string               `json:"mediaType"`
	VerificationMaterial verificationMaterial `json:"verificationMaterial"`
	DSSEEnvelope         bundleDSSEEnvelope   `json:"dsseEnvelope"`
}

type verificationMaterial struct {
	PublicKey publicKeyRef `json:"publicKey"`
}

type publicKeyRef struct {
	Hint string `json:"hint"`
}

type bundleDSSEEnvelope struct {
	Payload     string            `json:"payload"`
	PayloadType string            `json:"payloadType"`
	Signatures  []bundleSignature `json:"signatures"`
}

type bundleSignature struct {
	Sig string `json:"sig"`
}

func WrapInBundle(envelopeJSON []byte, publicKey crypto.PublicKey) ([]byte, error) {
	var raw struct {
		Payload     string `json:"payload"`
		PayloadType string `json:"payloadType"`
		Signatures  []struct {
			Sig string `json:"sig"`
		} `json:"signatures"`
	}
	if err := json.Unmarshal(envelopeJSON, &raw); err != nil {
		return nil, fmt.Errorf("parse dsse envelope for bundle wrapping: %w", err)
	}

	hint, err := publicKeyHint(publicKey)
	if err != nil {
		return nil, fmt.Errorf("compute public key hint: %w", err)
	}

	sigs := make([]bundleSignature, len(raw.Signatures))
	for i, s := range raw.Signatures {
		sigs[i] = bundleSignature{Sig: s.Sig}
	}

	bundle := Bundle{
		MediaType: BundleMediaType,
		VerificationMaterial: verificationMaterial{
			PublicKey: publicKeyRef{Hint: hint},
		},
		DSSEEnvelope: bundleDSSEEnvelope{
			Payload:     raw.Payload,
			PayloadType: raw.PayloadType,
			Signatures:  sigs,
		},
	}

	out, err := json.Marshal(bundle)
	if err != nil {
		return nil, fmt.Errorf("marshal sigstore bundle: %w", err)
	}

	return out, nil
}

func UnwrapBundle(bundleJSON []byte) ([]byte, error) {
	var bundle Bundle
	if err := json.Unmarshal(bundleJSON, &bundle); err != nil {
		return nil, fmt.Errorf("unmarshal sigstore bundle: %w", err)
	}

	if bundle.MediaType != BundleMediaType {
		return nil, fmt.Errorf("unsupported bundle media type: %s", bundle.MediaType)
	}

	envelope := struct {
		Payload     string            `json:"payload"`
		PayloadType string            `json:"payloadType"`
		Signatures  []bundleSignature `json:"signatures"`
	}{
		Payload:     bundle.DSSEEnvelope.Payload,
		PayloadType: bundle.DSSEEnvelope.PayloadType,
		Signatures:  bundle.DSSEEnvelope.Signatures,
	}

	out, err := json.Marshal(envelope)
	if err != nil {
		return nil, fmt.Errorf("marshal dsse envelope from bundle: %w", err)
	}

	return out, nil
}

func publicKeyHint(pub crypto.PublicKey) (string, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", fmt.Errorf("marshal public key to PKIX: %w", err)
	}

	digest := sha256.Sum256(der)
	return base64.StdEncoding.EncodeToString(digest[:]), nil
}
