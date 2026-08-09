package image_test

import (
	"context"
	"encoding/json"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/werf/werf/v2/pkg/attestation"
	"github.com/werf/werf/v2/pkg/oci/artifact"
	"github.com/werf/werf/v2/pkg/vex"
	veximage "github.com/werf/werf/v2/pkg/vex/image"
)

var _ = Describe("PullVEX", func() {
	Describe("attestation unwrapping", func() {
		It("round-trips known VEX JSON through wrap and unwrap", func() {
			vexJSON := []byte(`{"@context":"https://openvex.dev/ns/v0.2.0","statements":[]}`)
			digestHex, err := artifact.DigestHex("sha256:5d68d4300015200b8797ddf93a5dee3491fd2f6c0211d70a6ab8127ea053375a")
			Expect(err).ToNot(HaveOccurred())

			stmtBytes, err := attestation.WrapInInTotoStatement(vexJSON, vex.VEXPredicateURI, "test/repo", digestHex)
			Expect(err).ToNot(HaveOccurred())

			envelopeBytes, err := attestation.WrapInDSSE(context.Background(), stmtBytes, veximage.InTotoMediaType, nil)
			Expect(err).ToNot(HaveOccurred())

			// Simulate PullVEX unwrapping
			unwrappedStmt, err := attestation.UnwrapDSSE(envelopeBytes, veximage.InTotoMediaType)
			Expect(err).ToNot(HaveOccurred())

			predicate, predicateType, err := attestation.UnwrapInTotoStatement(unwrappedStmt)
			Expect(err).ToNot(HaveOccurred())
			Expect(predicateType).To(Equal(vex.VEXPredicateURI))
			Expect(predicate).To(MatchJSON(vexJSON))
		})

		It("rejects an in-toto statement with a wrong predicate type", func() {
			vexJSON := []byte(`{"@context":"https://openvex.dev/ns/v0.2.0","statements":[]}`)
			digestHex, err := artifact.DigestHex("sha256:5d68d4300015200b8797ddf93a5dee3491fd2f6c0211d70a6ab8127ea053375a")
			Expect(err).ToNot(HaveOccurred())

			wrongPredicateType := "https://example.com/wrong"

			stmtBytes, err := attestation.WrapInInTotoStatement(vexJSON, wrongPredicateType, "test/repo", digestHex)
			Expect(err).ToNot(HaveOccurred())

			envelopeBytes, err := attestation.WrapInDSSE(context.Background(), stmtBytes, veximage.InTotoMediaType, nil)
			Expect(err).ToNot(HaveOccurred())

			// Simulate PullVEX unwrapping
			unwrappedStmt, err := attestation.UnwrapDSSE(envelopeBytes, veximage.InTotoMediaType)
			Expect(err).ToNot(HaveOccurred())

			_, predicateType, err := attestation.UnwrapInTotoStatement(unwrappedStmt)
			Expect(err).ToNot(HaveOccurred())
			Expect(predicateType).ToNot(Equal(vex.VEXPredicateURI))
		})
	})
})

var _ = Describe("PushVEX", func() {
	DescribeTable("error cases",
		func(vexJSON []byte, repo, parentDigest, imageName, checksum, targetPlatform, expectedErr string) {
			err := veximage.PushVEX(context.Background(), vexJSON, repo, parentDigest, imageName, checksum, targetPlatform)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring(expectedErr))
		},
		Entry("invalid parentDigest", []byte(`{"@context":"https://openvex.dev/ns/v0.2.0","statements":[]}`), "test/repo", "not-a-digest", "my-image", "abc123", "linux/amd64", "extract digest hex"),
	)

	Describe("attestation wrapping", func() {
		It("produces a valid in-toto statement", func() {
			vexJSON := []byte(`{"@context":"https://openvex.dev/ns/v0.2.0","statements":[]}`)
			digestHex, err := artifact.DigestHex("sha256:5d68d4300015200b8797ddf93a5dee3491fd2f6c0211d70a6ab8127ea053375a")
			Expect(err).ToNot(HaveOccurred())

			stmtBytes, err := attestation.WrapInInTotoStatement(vexJSON, "https://openvex.dev/ns/v0.2.0", "test/repo", digestHex)
			Expect(err).ToNot(HaveOccurred())
			Expect(stmtBytes).ToNot(BeEmpty())

			Expect(stmtBytes).To(MatchJSON(`{
				"_type": "https://in-toto.io/Statement/v1",
				"predicateType": "https://openvex.dev/ns/v0.2.0",
				"subject": [{"name": "test/repo", "digest": {"sha256": "5d68d4300015200b8797ddf93a5dee3491fd2f6c0211d70a6ab8127ea053375a"}}],
				"predicate": {"@context":"https://openvex.dev/ns/v0.2.0","statements":[]}
			}`))
		})

		It("wraps the in-toto statement in a DSSE envelope", func() {
			vexJSON := []byte(`{"@context":"https://openvex.dev/ns/v0.2.0","statements":[]}`)
			digestHex, err := artifact.DigestHex("sha256:5d68d4300015200b8797ddf93a5dee3491fd2f6c0211d70a6ab8127ea053375a")
			Expect(err).ToNot(HaveOccurred())

			stmtBytes, err := attestation.WrapInInTotoStatement(vexJSON, "https://openvex.dev/ns/v0.2.0", "test/repo", digestHex)
			Expect(err).ToNot(HaveOccurred())

			envelopeBytes, err := attestation.WrapInDSSE(context.Background(), stmtBytes, "application/vnd.in-toto+json", nil)
			Expect(err).ToNot(HaveOccurred())
			Expect(envelopeBytes).ToNot(BeEmpty())

			var envelope map[string]interface{}
			Expect(json.Unmarshal(envelopeBytes, &envelope)).To(Succeed())
			Expect(envelope).To(HaveKey("payloadType"))
			Expect(envelope["payloadType"]).To(Equal("application/vnd.in-toto+json"))
			Expect(envelope).To(HaveKey("payload"))
			Expect(envelope).To(HaveKey("signatures"))
		})
	})
})
