package attestation

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("ResolvePredicateType", func() {
	DescribeTable("well-known short names",
		func(short, expectedURI string) {
			uri, err := ResolvePredicateType(short)
			Expect(err).NotTo(HaveOccurred())
			Expect(uri).To(Equal(expectedURI))
		},
		Entry("openvex", "openvex", "https://openvex.dev/ns/v0.2.0"),
		Entry("slsaprovenance", "slsaprovenance", "https://slsa.dev/provenance/v0.2"),
		Entry("slsaprovenance1", "slsaprovenance1", "https://slsa.dev/provenance/v1"),
		Entry("spdxjson", "spdxjson", "https://spdx.dev/Document"),
		Entry("cyclonedx", "cyclonedx", "https://cyclonedx.org/bom"),
	)

	DescribeTable("URI passthrough",
		func(uri string) {
			result, err := ResolvePredicateType(uri)
			Expect(err).NotTo(HaveOccurred())
			Expect(result).To(Equal(uri))
		},
		Entry("https URI", "https://custom.example.com/predicate/v1"),
		Entry("http URI", "http://internal.corp/v2"),
		Entry("custom scheme", "custom://my-predicate/v1"),
	)

	It("should error on unknown short name", func() {
		_, err := ResolvePredicateType("nonexistent")
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("unknown predicate type"))
		Expect(err.Error()).To(ContainSubstring("nonexistent"))
	})

	It("should error on empty string", func() {
		_, err := ResolvePredicateType("")
		Expect(err).To(HaveOccurred())
	})

	It("should list available types in error message", func() {
		_, err := ResolvePredicateType("bad")
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("openvex"))
		Expect(err.Error()).To(ContainSubstring("cyclonedx"))
	})
})
