package image

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/secure-systems-lab/go-securesystemslib/dsse"
	"github.com/sigstore/sigstore/pkg/signature"

	"github.com/werf/werf/v2/pkg/attestation"
)

func generateKeyPair() (signature.Signer, signature.Verifier) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	Expect(err).NotTo(HaveOccurred())
	sv, err := signature.LoadECDSASignerVerifier(key, crypto.SHA256)
	Expect(err).NotTo(HaveOccurred())
	return sv, sv
}

type failingSigner struct{}

func (failingSigner) SignMessage(message io.Reader, opts ...signature.SignOption) ([]byte, error) {
	return nil, fmt.Errorf("deliberate signing failure")
}

func (failingSigner) PublicKey(opts ...signature.PublicKeyOption) (crypto.PublicKey, error) {
	return nil, fmt.Errorf("deliberate public key failure")
}

var _ signature.Signer = failingSigner{}

var _ = Describe("DSSE Envelope", func() {
	payload := []byte(`{"bomFormat":"CycloneDX","version":1}`)
	payloadType := attestation.DSSEMediaType

	DescribeTable("WrapInDSSE / UnwrapDSSE round-trip (unsigned)",
		func(ctx SpecContext, payload []byte, payloadType string) {
			envelopeJSON, err := WrapInDSSE(ctx, payload, payloadType, nil)
			Expect(err).To(Succeed())
			Expect(envelopeJSON).ToNot(BeEmpty())

			result, err := UnwrapDSSE(envelopeJSON, payloadType)
			Expect(err).To(Succeed())
			Expect(result).To(Equal(payload))
		},
		Entry("simple JSON payload", payload, payloadType),
		Entry("empty payload", []byte{}, payloadType),
		Entry("binary payload", []byte{0x00, 0x01, 0x02}, payloadType),
	)

	It("should fail on wrong payloadType", func(ctx SpecContext) {
		envelopeJSON, err := WrapInDSSE(ctx, payload, payloadType, nil)
		Expect(err).To(Succeed())

		_, err = UnwrapDSSE(envelopeJSON, "application/vnd.wrong+json")
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("unexpected DSSE payloadType"))
	})

	It("should fail on malformed JSON", func() {
		_, err := UnwrapDSSE([]byte("{bad json}"), payloadType)
		Expect(err).To(HaveOccurred())
	})

	Describe("nil signer produces unsigned envelope", func() {
		It("should produce empty signatures array", func(ctx SpecContext) {
			envelopeJSON, err := WrapInDSSE(ctx, payload, payloadType, nil)
			Expect(err).NotTo(HaveOccurred())

			Expect(attestation.HasSignatures(envelopeJSON)).To(BeFalse())

			var env dsse.Envelope
			Expect(json.Unmarshal(envelopeJSON, &env)).To(Succeed())
			Expect(env.Signatures).To(BeEmpty())
		})
	})

	Describe("non-nil ECDSA signer produces signed envelope", func() {
		It("should have signatures and verify with matching verifier", func(ctx SpecContext) {
			signer, verifier := generateKeyPair()

			envelopeJSON, err := WrapInDSSE(ctx, payload, payloadType, signer)
			Expect(err).NotTo(HaveOccurred())

			Expect(attestation.HasSignatures(envelopeJSON)).To(BeTrue())

			result, err := attestation.VerifyDSSE(ctx, envelopeJSON, payloadType, []signature.Verifier{verifier})
			Expect(err).NotTo(HaveOccurred())
			Expect(result).To(Equal(payload))
		})
	})

	Describe("signer that errors", func() {
		It("should return wrapped error", func(ctx SpecContext) {
			_, err := WrapInDSSE(ctx, payload, payloadType, failingSigner{})
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("deliberate signing failure"))
		})
	})

	Describe("corrupt signature byte rejects verification", func() {
		It("should fail VerifyDSSE after corruption", func(ctx SpecContext) {
			signer, verifier := generateKeyPair()

			envelopeJSON, err := WrapInDSSE(ctx, payload, payloadType, signer)
			Expect(err).NotTo(HaveOccurred())

			var env dsse.Envelope
			Expect(json.Unmarshal(envelopeJSON, &env)).To(Succeed())
			Expect(env.Signatures).To(HaveLen(1))

			sigBytes, err := base64.StdEncoding.DecodeString(env.Signatures[0].Sig)
			Expect(err).NotTo(HaveOccurred())
			Expect(sigBytes).NotTo(BeEmpty())

			sigBytes[0] ^= 0xFF
			env.Signatures[0].Sig = base64.StdEncoding.EncodeToString(sigBytes)

			corruptedJSON, err := json.Marshal(env)
			Expect(err).NotTo(HaveOccurred())

			_, err = attestation.VerifyDSSE(ctx, corruptedJSON, payloadType, []signature.Verifier{verifier})
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("signature verification failed"))
		})
	})
})

var _ = Describe("In-Toto Statement", func() {
	predicate := []byte(`{"bomFormat":"CycloneDX","version":1}`)
	predicateType := CycloneDX16Predicate
	repo := "registry.example.com/project"
	digestHex := "abc123def456"

	DescribeTable("WrapInInTotoStatement / UnwrapInTotoStatement round-trip",
		func(predicate []byte, predicateType, repo, digestHex string) {
			stmtJSON, err := WrapInInTotoStatement(predicate, predicateType, repo, digestHex)
			Expect(err).To(Succeed())
			Expect(stmtJSON).ToNot(BeEmpty())

			resultPredicate, resultType, err := UnwrapInTotoStatement(stmtJSON)
			Expect(err).To(Succeed())
			Expect(resultType).To(Equal(predicateType))
			Expect(json.RawMessage(resultPredicate)).To(MatchJSON(predicate))
		},
		Entry("CycloneDX predicate", predicate, predicateType, repo, digestHex),
		Entry("different digest", []byte(`{"key":"val"}`), predicateType, "other.io/repo", "xyz789"),
		Entry("empty predicate", []byte(`{}`), predicateType, repo, digestHex),
	)

	It("should produce valid in-toto v1 statement structure", func() {
		stmtJSON, err := WrapInInTotoStatement(predicate, predicateType, repo, digestHex)
		Expect(err).To(Succeed())

		var stmt map[string]interface{}
		Expect(json.Unmarshal(stmtJSON, &stmt)).To(Succeed())

		Expect(stmt["_type"]).To(Equal(attestation.InTotoStatementType))
		Expect(stmt["predicateType"]).To(Equal(predicateType))

		subjects, ok := stmt["subject"].([]interface{})
		Expect(ok).To(BeTrue())
		Expect(subjects).To(HaveLen(1))

		subj, ok := subjects[0].(map[string]interface{})
		Expect(ok).To(BeTrue())
		Expect(subj["name"]).To(Equal(repo))

		digests, ok := subj["digest"].(map[string]interface{})
		Expect(ok).To(BeTrue())
		Expect(digests["sha256"]).To(Equal(digestHex))
	})

	It("should fail on unknown statement type", func() {
		stmtJSON, err := WrapInInTotoStatement(predicate, predicateType, repo, digestHex)
		Expect(err).To(Succeed())

		var raw map[string]json.RawMessage
		Expect(json.Unmarshal(stmtJSON, &raw)).To(Succeed())
		raw["_type"] = json.RawMessage(`"https://in-toto.io/Statement/v0.1"`)
		modified, err := json.Marshal(raw)
		Expect(err).To(Succeed())

		_, _, err = UnwrapInTotoStatement(modified)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("unexpected in-toto statement type"))
	})
})

// Verify failingSigner and generateKeyPair produce correct interface match.
var _ = Describe("unsigned/signed envelope structure equality", func() {
	It("nil signer envelope structure matches pre-change format", func(ctx SpecContext) {
		payload := []byte(`{"test":true}`)

		envelopeJSON, err := WrapInDSSE(ctx, payload, "application/test", nil)
		Expect(err).NotTo(HaveOccurred())

		var env dsse.Envelope
		Expect(json.Unmarshal(envelopeJSON, &env)).To(Succeed())
		Expect(env.PayloadType).To(Equal("application/test"))
		Expect(env.Signatures).To(BeEmpty())

		decoded, err := base64.StdEncoding.DecodeString(env.Payload)
		Expect(err).NotTo(HaveOccurred())
		Expect(decoded).To(Equal(payload))
	})
})
