package convergefailure

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("DependencyImageNames", func() {
	It("collects base images and internal import sources, skipping external imports and empty bases", func() {
		deps := []ImageDependencies{
			{
				BaseImageName: "builder/golang",
				Imports: []ImportSource{
					{ImageName: "src-artifact"},
					{ImageName: "registry.example.com/external:tag", External: true},
				},
			},
			{
				BaseImageName: "",
				Imports:       []ImportSource{{ImageName: "another-artifact"}},
			},
		}

		Expect(DependencyImageNames(deps)).To(Equal([]string{"builder/golang", "src-artifact", "another-artifact"}))
	})

	It("returns nothing for an image with no in-project dependencies", func() {
		deps := []ImageDependencies{{
			Imports: []ImportSource{{ImageName: "registry.example.com/external:tag", External: true}},
		}}

		Expect(DependencyImageNames(deps)).To(BeEmpty())
	})
})

var _ = Describe("compactCause", func() {
	DescribeTable("summarizes component details",
		func(details, expected string) {
			Expect(compactCause(details)).To(Equal(expected))
		},
		Entry("single component", "    - component: apk-tools (pkg:apk/alpine/apk-tools@1.0.0): empty url\n", "component: apk-tools (pkg:apk/alpine/apk-tools@1.0.0): empty url"),
		Entry("multiple components", "    - component: apk-tools (pkg:apk/alpine/apk-tools@1.0.0): empty url\n    - component: openssl (pkg:apk/alpine/openssl@1.0.0): empty url\n", "component: apk-tools (pkg:apk/alpine/apk-tools@1.0.0): empty url (and 1 more component errors)"),
		Entry("empty details", "", "external references enrichment failed"),
	)
})

var _ = Describe("Tracker.AggregatedError", func() {
	It("returns nil when nothing failed", func() {
		Expect(NewTracker("https://refs.example.com").AggregatedError(3)).To(Succeed())
	})

	It("keeps the direct-failure format byte-identical", func() {
		tracker := newTrackerWithRecords(map[string]Record{
			"img1": {
				Details:   "    - component: apk-tools (pkg:apk/alpine/apk-tools@1.0.0): empty url\n",
				RootImage: "img1",
				RootCause: "component: apk-tools (pkg:apk/alpine/apk-tools@1.0.0): empty url",
			},
		})

		err := tracker.AggregatedError(1)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(Equal("resolve external references: 1 of 1 images failed:\n  - image: img1:\n    - component: apk-tools (pkg:apk/alpine/apk-tools@1.0.0): empty url\n"))
	})

	It("renders skip records and counts them in the summary", func() {
		tracker := newTrackerWithRecords(map[string]Record{
			"a": {
				Details:   "    - component: apk-tools (pkg:apk/alpine/apk-tools@1.0.0): empty url\n",
				RootImage: "a",
				RootCause: "component: apk-tools (pkg:apk/alpine/apk-tools@1.0.0): empty url",
			},
			"b": {
				RootImage: "a",
				RootCause: "component: apk-tools (pkg:apk/alpine/apk-tools@1.0.0): empty url",
			},
		})

		err := tracker.AggregatedError(3)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("resolve external references: 2 of 3 images failed:"))
		Expect(err.Error()).To(ContainSubstring("  - image: a:\n    - component: apk-tools (pkg:apk/alpine/apk-tools@1.0.0): empty url"))
		Expect(err.Error()).To(ContainSubstring("  - image: b:\n    - skipped: SBOM for image \"a\" was not generated: component: apk-tools (pkg:apk/alpine/apk-tools@1.0.0): empty url"))
	})
})
