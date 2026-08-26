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

var _ = Describe("PredicateKindAliases", func() {
	DescribeTable("alias sets",
		func(shortOrURI string, expected []string) {
			aliases, err := PredicateKindAliases(shortOrURI)
			Expect(err).NotTo(HaveOccurred())
			Expect(aliases).To(Equal(expected))
		},
		Entry("openvex short name", "openvex", []string{"https://openvex.dev/ns", "https://openvex.dev/ns/v0.2.0"}),
		Entry("openvex unversioned URI", "https://openvex.dev/ns", []string{"https://openvex.dev/ns", "https://openvex.dev/ns/v0.2.0"}),
		Entry("openvex versioned URI", "https://openvex.dev/ns/v0.2.0", []string{"https://openvex.dev/ns", "https://openvex.dev/ns/v0.2.0"}),
		Entry("cyclonedx short name", "cyclonedx", []string{"https://cyclonedx.org/bom", "https://cyclonedx.org/bom/v1.6"}),
		Entry("cyclonedx versioned URI", "https://cyclonedx.org/bom/v1.6", []string{"https://cyclonedx.org/bom", "https://cyclonedx.org/bom/v1.6"}),
		Entry("unknown kind resolves to itself", "https://slsa.dev/provenance/v1", []string{"https://slsa.dev/provenance/v1"}),
		Entry("custom URI resolves to itself", "https://custom.example.com/predicate/v1", []string{"https://custom.example.com/predicate/v1"}),
	)

	It("should error on unknown short name", func() {
		_, err := PredicateKindAliases("nonexistent")
		Expect(err).To(HaveOccurred())
	})
})

var _ = Describe("PredicateTypeMatches", func() {
	DescribeTable("matching",
		func(requested, found string, expected bool) {
			Expect(PredicateTypeMatches(requested, found)).To(Equal(expected))
		},
		Entry("exact match", "https://slsa.dev/provenance/v1", "https://slsa.dev/provenance/v1", true),
		Entry("exact mismatch", "https://slsa.dev/provenance/v1", "https://slsa.dev/provenance/v0.2", false),
		Entry("openvex unversioned accepts versioned", "https://openvex.dev/ns", "https://openvex.dev/ns/v0.2.0", true),
		Entry("openvex versioned accepts unversioned", "https://openvex.dev/ns/v0.2.0", "https://openvex.dev/ns", true),
		Entry("openvex rejects foreign predicate", "https://openvex.dev/ns", "https://cyclonedx.org/bom", false),
		Entry("cyclonedx stays exact: unversioned rejects versioned", "https://cyclonedx.org/bom", "https://cyclonedx.org/bom/v1.6", false),
		Entry("cyclonedx stays exact: versioned rejects unversioned", "https://cyclonedx.org/bom/v1.6", "https://cyclonedx.org/bom", false),
	)
})
