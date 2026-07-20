package attestation

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"

	"github.com/secure-systems-lab/go-securesystemslib/dsse"
	"github.com/sigstore/sigstore/pkg/signature"
)

const (
	DSSEMediaType   = "application/vnd.dsse.envelope.v1+json"
	InTotoMediaType = "application/vnd.in-toto+json"
)

func WrapInDSSE(ctx context.Context, payload []byte, payloadType string, signer signature.Signer) ([]byte, error) {
	envelope := dsse.Envelope{
		PayloadType: payloadType,
		Payload:     base64.StdEncoding.EncodeToString(payload),
		Signatures:  []dsse.Signature{},
	}

	if signer != nil {
		pae := dsse.PAE(payloadType, payload)

		sig, err := signer.SignMessage(bytes.NewReader(pae))
		if err != nil {
			return nil, fmt.Errorf("sign DSSE PAE: %w", err)
		}

		envelope.Signatures = []dsse.Signature{{
			Sig: base64.StdEncoding.EncodeToString(sig),
		}}
	}

	envelopeBytes, err := json.Marshal(envelope)
	if err != nil {
		return nil, fmt.Errorf("marshal DSSE envelope: %w", err)
	}

	return envelopeBytes, nil
}

func UnwrapDSSE(envelopeJSON []byte, expectedPayloadType string) ([]byte, error) {
	var envelope dsse.Envelope
	if err := json.Unmarshal(envelopeJSON, &envelope); err != nil {
		return nil, fmt.Errorf("unmarshal DSSE envelope: %w", err)
	}

	if envelope.PayloadType != expectedPayloadType {
		return nil, fmt.Errorf("unexpected DSSE payloadType %q, expected %q", envelope.PayloadType, expectedPayloadType)
	}

	payload, err := envelope.DecodeB64Payload()
	if err != nil {
		return nil, fmt.Errorf("decode DSSE payload: %w", err)
	}

	return payload, nil
}

func VerifyDSSE(ctx context.Context, envelopeJSON []byte, expectedPayloadType string, verifiers []signature.Verifier) ([]byte, error) {
	var envelope dsse.Envelope
	if err := json.Unmarshal(envelopeJSON, &envelope); err != nil {
		return nil, fmt.Errorf("unmarshal DSSE envelope: %w", err)
	}

	if envelope.PayloadType != expectedPayloadType {
		return nil, fmt.Errorf("unexpected DSSE payloadType %q, expected %q", envelope.PayloadType, expectedPayloadType)
	}

	if len(envelope.Signatures) == 0 {
		return nil, fmt.Errorf("DSSE envelope has no signatures")
	}

	payload, err := envelope.DecodeB64Payload()
	if err != nil {
		return nil, fmt.Errorf("decode DSSE payload: %w", err)
	}

	pae := dsse.PAE(envelope.PayloadType, payload)

	var decodeErrs int
	for _, envSig := range envelope.Signatures {
		sigBytes, err := base64.StdEncoding.DecodeString(envSig.Sig)
		if err != nil {
			decodeErrs++
			continue
		}

		for _, v := range verifiers {
			if err := v.VerifySignature(bytes.NewReader(sigBytes), bytes.NewReader(pae)); err == nil {
				return payload, nil
			}
		}
	}

	if decodeErrs > 0 {
		return nil, fmt.Errorf("DSSE signature verification failed: no matching verifier found (%d of %d signatures had invalid base64 encoding)", decodeErrs, len(envelope.Signatures))
	}

	return nil, fmt.Errorf("DSSE signature verification failed: no matching verifier found")
}

func HasSignatures(envelopeJSON []byte) (bool, error) {
	var envelope dsse.Envelope
	if err := json.Unmarshal(envelopeJSON, &envelope); err != nil {
		return false, fmt.Errorf("unmarshal DSSE envelope: %w", err)
	}
	return len(envelope.Signatures) > 0, nil
}
