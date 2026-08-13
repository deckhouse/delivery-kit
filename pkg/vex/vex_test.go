package vex_test

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/werf/werf/v2/pkg/vex"
)

var _ = Describe("ValidateVEXDocument", func() {
	DescribeTable("valid documents",
		func(data []byte) {
			Expect(vex.ValidateVEXDocument(data)).To(Succeed())
		},
		Entry("valid OpenVEX document", []byte(`{"@context":"https://openvex.dev/ns/v0.2.0","statements":[]}`)),
		Entry("valid OpenVEX document with statements", []byte(`{"@context":"https://openvex.dev/ns/v0.2.0","statements":[{"id":"test","status":"not_affected"}]}`)),
	)

	DescribeTable("invalid documents",
		func(data []byte, match string) {
			err := vex.ValidateVEXDocument(data)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring(match))
		},
		Entry("empty document", []byte{}, "VEX document is empty"),
		Entry("non-JSON content", []byte("not json"), "not valid JSON"),
		Entry("wrong @context", []byte(`{"@context":"https://example.com","statements":[]}`), "unexpected @context"),
		Entry("missing @context field", []byte(`{"statements":[]}`), "unexpected @context"),
	)
})
