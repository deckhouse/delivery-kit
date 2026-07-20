package attestation

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/sigstore/sigstore/pkg/signature"
)

var _ = Describe("Attestation integration", func() {
	var (
		signerA, signerB     signature.Signer
		verifierA, verifierB signature.Verifier
		predicate            []byte
		resolvedType         string
		envelopeJSON         []byte
	)

	BeforeEach(func(ctx SpecContext) {
		signerA, verifierA = generateKeyPair()
		signerB, verifierB = generateKeyPair()

		predicate = []byte(`{"@context":"https://openvex.dev/ns/v0.2.0","@id":"test","statements":[{"vulnerability":{"name":"CVE-2024-1234"},"products":[{"@id":"pkg:oci/test@sha256:abc"}],"status":"not_affected","justification":"vulnerable_code_not_in_execute_path"}]}`)

		var err error
		resolvedType, err = ResolvePredicateType("openvex")
		Expect(err).NotTo(HaveOccurred())

		stmtBytes, err := WrapInInTotoStatement(predicate, resolvedType, "registry.example.com/test", "abc123def456789")
		Expect(err).NotTo(HaveOccurred())

		envelopeJSON, err = WrapInDSSE(ctx, stmtBytes, InTotoMediaType, signerA)
		Expect(err).NotTo(HaveOccurred())

		_ = signerB
	})

	Describe("sign → verify round-trip", func() {
		It("should verify with correct key and return matching predicate", func(ctx SpecContext) {
			payload, err := VerifyDSSE(ctx, envelopeJSON, InTotoMediaType, []signature.Verifier{verifierA})
			Expect(err).NotTo(HaveOccurred())

			resultPredicate, resultType, err := UnwrapInTotoStatement(payload)
			Expect(err).NotTo(HaveOccurred())
			Expect(resultType).To(Equal(resolvedType))
			Expect(resultPredicate).To(MatchJSON(predicate))
		})

		It("should fail verify with wrong key", func(ctx SpecContext) {
			_, err := VerifyDSSE(ctx, envelopeJSON, InTotoMediaType, []signature.Verifier{verifierB})
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("signature verification failed"))
		})

		It("should succeed when any of multiple verifiers matches", func(ctx SpecContext) {
			payload, err := VerifyDSSE(ctx, envelopeJSON, InTotoMediaType, []signature.Verifier{verifierB, verifierA})
			Expect(err).NotTo(HaveOccurred())

			resultPredicate, _, err := UnwrapInTotoStatement(payload)
			Expect(err).NotTo(HaveOccurred())
			Expect(resultPredicate).To(MatchJSON(predicate))
		})

		It("should get without verify (returns predicate)", func() {
			payload, err := UnwrapDSSE(envelopeJSON, InTotoMediaType)
			Expect(err).NotTo(HaveOccurred())

			resultPredicate, resultType, err := UnwrapInTotoStatement(payload)
			Expect(err).NotTo(HaveOccurred())
			Expect(resultType).To(Equal(resolvedType))
			Expect(resultPredicate).To(MatchJSON(predicate))
		})
	})

	Describe("unsigned envelope", func() {
		It("should fail verification", func(ctx SpecContext) {
			stmtBytes, err := WrapInInTotoStatement(predicate, resolvedType, "repo", "hex")
			Expect(err).NotTo(HaveOccurred())

			unsignedEnvelope, err := WrapInDSSE(ctx, stmtBytes, InTotoMediaType, nil)
			Expect(err).NotTo(HaveOccurred())
			Expect(HasSignatures(unsignedEnvelope)).To(BeFalse())

			_, err = VerifyDSSE(ctx, unsignedEnvelope, InTotoMediaType, []signature.Verifier{verifierA})
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("no signatures"))
		})
	})

	DescribeTable("malformed input handling",
		func(ctx SpecContext, fn func(SpecContext)) {
			fn(ctx)
		},
		Entry("UnwrapDSSE with garbage", func(_ SpecContext) {
			_, err := UnwrapDSSE([]byte("not json"), InTotoMediaType)
			Expect(err).To(HaveOccurred())
		}),
		Entry("UnwrapInTotoStatement with garbage", func(_ SpecContext) {
			_, _, err := UnwrapInTotoStatement([]byte("not json"))
			Expect(err).To(HaveOccurred())
		}),
		Entry("VerifyDSSE with garbage", func(ctx SpecContext) {
			_, v := generateKeyPair()
			_, err := VerifyDSSE(ctx, []byte("not json"), InTotoMediaType, []signature.Verifier{v})
			Expect(err).To(HaveOccurred())
		}),
		Entry("WrapInDSSE with nil signer produces unsigned envelope", func(ctx SpecContext) {
			envelope, err := WrapInDSSE(ctx, []byte("payload"), "type", nil)
			Expect(err).NotTo(HaveOccurred())
			Expect(HasSignatures(envelope)).To(BeFalse())
		}),
		Entry("WrapInDSSE with empty payload still signs", func(ctx SpecContext) {
			s, _ := generateKeyPair()
			envelope, err := WrapInDSSE(ctx, []byte{}, "type", s)
			Expect(err).NotTo(HaveOccurred())
			Expect(HasSignatures(envelope)).To(BeTrue())
		}),
	)
})
