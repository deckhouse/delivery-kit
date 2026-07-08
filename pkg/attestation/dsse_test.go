package attestation

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/sigstore/sigstore/pkg/signature"
)

func generateKeyPair() (signature.Signer, signature.Verifier) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	Expect(err).NotTo(HaveOccurred())
	sv, err := signature.LoadECDSASignerVerifier(key, crypto.SHA256)
	Expect(err).NotTo(HaveOccurred())
	return sv, sv
}

var _ = Describe("DSSE Envelope", func() {
	ctx := context.Background()

	DescribeTable("WrapInDSSE / UnwrapDSSE round-trip (unsigned)",
		func(payload []byte, payloadType string) {
			envelopeJSON, err := WrapInDSSE(ctx, payload, payloadType, nil)
			Expect(err).NotTo(HaveOccurred())
			Expect(envelopeJSON).NotTo(BeEmpty())

			result, err := UnwrapDSSE(envelopeJSON, payloadType)
			Expect(err).NotTo(HaveOccurred())
			Expect(result).To(Equal(payload))
		},
		Entry("simple JSON payload", []byte(`{"test":"data"}`), "application/vnd.test+json"),
		Entry("empty payload", []byte{}, "application/vnd.test+json"),
		Entry("binary payload", []byte{0x00, 0x01, 0x02}, "application/vnd.test+json"),
	)

	It("should fail UnwrapDSSE with wrong payloadType", func() {
		envelopeJSON, err := WrapInDSSE(ctx, []byte(`{"x":1}`), "application/correct", nil)
		Expect(err).NotTo(HaveOccurred())

		_, err = UnwrapDSSE(envelopeJSON, "application/wrong")
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("unexpected DSSE payloadType"))
	})

	It("should fail UnwrapDSSE with malformed JSON", func() {
		_, err := UnwrapDSSE([]byte("{bad json}"), "any")
		Expect(err).To(HaveOccurred())
	})

	Describe("signed envelopes", func() {
		It("should sign, then verify with correct key", func() {
			signer, verifier := generateKeyPair()
			payload := []byte(`{"vulnerability":"CVE-2024-1234"}`)

			envelopeJSON, err := WrapInDSSE(ctx, payload, InTotoMediaType, signer)
			Expect(err).NotTo(HaveOccurred())
			Expect(HasSignatures(envelopeJSON)).To(BeTrue())

			result, err := VerifyDSSE(ctx, envelopeJSON, InTotoMediaType, []signature.Verifier{verifier})
			Expect(err).NotTo(HaveOccurred())
			Expect(result).To(Equal(payload))
		})

		It("should fail verify with wrong key", func() {
			signerA, _ := generateKeyPair()
			_, verifierB := generateKeyPair()

			envelopeJSON, err := WrapInDSSE(ctx, []byte(`{"x":1}`), InTotoMediaType, signerA)
			Expect(err).NotTo(HaveOccurred())

			_, err = VerifyDSSE(ctx, envelopeJSON, InTotoMediaType, []signature.Verifier{verifierB})
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("signature verification failed"))
		})

		It("should fail verify on unsigned envelope", func() {
			envelopeJSON, err := WrapInDSSE(ctx, []byte(`{"x":1}`), InTotoMediaType, nil)
			Expect(err).NotTo(HaveOccurred())
			Expect(HasSignatures(envelopeJSON)).To(BeFalse())

			_, verifier := generateKeyPair()
			_, err = VerifyDSSE(ctx, envelopeJSON, InTotoMediaType, []signature.Verifier{verifier})
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("no signatures"))
		})

		It("should succeed verify when any of multiple verifiers matches", func() {
			signerA, verifierA := generateKeyPair()
			_, verifierB := generateKeyPair()

			envelopeJSON, err := WrapInDSSE(ctx, []byte(`{"x":"multi"}`), InTotoMediaType, signerA)
			Expect(err).NotTo(HaveOccurred())

			result, err := VerifyDSSE(ctx, envelopeJSON, InTotoMediaType, []signature.Verifier{verifierB, verifierA})
			Expect(err).NotTo(HaveOccurred())
			Expect(result).To(Equal([]byte(`{"x":"multi"}`)))
		})

		It("should fail VerifyDSSE with malformed JSON", func() {
			_, verifier := generateKeyPair()
			_, err := VerifyDSSE(ctx, []byte("not json"), InTotoMediaType, []signature.Verifier{verifier})
			Expect(err).To(HaveOccurred())
		})
	})

	DescribeTable("HasSignatures",
		func(signer signature.Signer, expected bool) {
			envelope, err := WrapInDSSE(ctx, []byte("payload"), "type", signer)
			Expect(err).NotTo(HaveOccurred())
			Expect(HasSignatures(envelope)).To(Equal(expected))
		},
		Entry("unsigned", nil, false),
		func() TableEntry {
			s, _ := generateKeyPair()
			return Entry("signed", s, true)
		}(),
	)
})

var _ = Describe("In-Toto Statement", func() {
	DescribeTable("WrapInInTotoStatement / UnwrapInTotoStatement round-trip",
		func(predicate []byte, predicateType, repo, digestHex string) {
			stmtJSON, err := WrapInInTotoStatement(predicate, predicateType, repo, digestHex)
			Expect(err).NotTo(HaveOccurred())
			Expect(stmtJSON).NotTo(BeEmpty())

			resultPredicate, resultType, err := UnwrapInTotoStatement(stmtJSON)
			Expect(err).NotTo(HaveOccurred())
			Expect(resultType).To(Equal(predicateType))
			Expect(json.RawMessage(resultPredicate)).To(MatchJSON(predicate))
		},
		Entry("CycloneDX predicate", []byte(`{"bomFormat":"CycloneDX"}`), "https://cyclonedx.org/bom/v1.6", "registry.example.com/project", "abc123"),
		Entry("OpenVEX predicate", []byte(`{"@context":"https://openvex.dev/ns/v0.2.0"}`), "https://openvex.dev/ns/v0.2.0", "registry.io/app", "def456"),
		Entry("empty predicate", []byte(`{}`), "https://example.com/v1", "repo", "hex"),
	)

	It("should produce valid in-toto v1 structure", func() {
		stmtJSON, err := WrapInInTotoStatement([]byte(`{"k":"v"}`), "https://example.com/v1", "my.reg/repo", "deadbeef")
		Expect(err).NotTo(HaveOccurred())

		var stmt map[string]interface{}
		Expect(json.Unmarshal(stmtJSON, &stmt)).To(Succeed())
		Expect(stmt["_type"]).To(Equal(InTotoStatementType))
		Expect(stmt["predicateType"]).To(Equal("https://example.com/v1"))

		subjects, ok := stmt["subject"].([]interface{})
		Expect(ok).To(BeTrue())
		Expect(subjects).To(HaveLen(1))

		subj := subjects[0].(map[string]interface{})
		Expect(subj["name"]).To(Equal("my.reg/repo"))
		Expect(subj["digest"].(map[string]interface{})["sha256"]).To(Equal("deadbeef"))
	})

	It("should fail on wrong statement type", func() {
		stmtJSON, err := WrapInInTotoStatement([]byte(`{}`), "https://example.com/v1", "repo", "hex")
		Expect(err).NotTo(HaveOccurred())

		var raw map[string]json.RawMessage
		Expect(json.Unmarshal(stmtJSON, &raw)).To(Succeed())
		raw["_type"] = json.RawMessage(`"https://in-toto.io/Statement/v0.1"`)
		modified, err := json.Marshal(raw)
		Expect(err).NotTo(HaveOccurred())

		_, _, err = UnwrapInTotoStatement(modified)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("unexpected in-toto statement type"))
	})

	It("should fail on malformed JSON", func() {
		_, _, err := UnwrapInTotoStatement([]byte("not json"))
		Expect(err).To(HaveOccurred())
	})
})
