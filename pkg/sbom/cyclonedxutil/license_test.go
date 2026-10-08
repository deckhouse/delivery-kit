package cyclonedxutil

import (
	cdx "github.com/CycloneDX/cyclonedx-go"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("normalizeLicenses", func() {
	DescribeTable("puts every license into the field the schema allows for it",
		func(in cdx.Licenses, expected *cdx.Licenses) {
			Expect(normalizeLicenses(&in)).To(Equal(expected))

			bom := NewBOM()
			bom.Components = &[]cdx.Component{{Type: cdx.ComponentTypeLibrary, Name: "lib", Licenses: &in}}
			Canonicalize(GinkgoT().Context(), bom)
			Expect((*bom.Components)[0].Licenses).To(Equal(expected))

			data, err := ToJSON(bom)
			Expect(err).NotTo(HaveOccurred())
			Expect(ValidateCycloneDX16Schema(data)).To(Succeed())
		},

		Entry("a single SPDX id stays in license.id",
			cdx.Licenses{{License: &cdx.License{ID: "MIT"}}},
			&cdx.Licenses{{License: &cdx.License{ID: "MIT"}}}),

		Entry("an SPDX id that is not a plain license stays too",
			cdx.Licenses{{License: &cdx.License{ID: "curl"}}},
			&cdx.Licenses{{License: &cdx.License{ID: "curl"}}}),

		Entry("an SPDX expression in license.id becomes the expression",
			cdx.Licenses{{License: &cdx.License{ID: "Apache-2.0 OR MIT"}}},
			&cdx.Licenses{{Expression: "Apache-2.0 OR MIT"}}),

		Entry("an expression with an exception",
			cdx.Licenses{{License: &cdx.License{ID: "GPL-2.0-or-later WITH cryptsetup-OpenSSL-exception"}}},
			&cdx.Licenses{{Expression: "GPL-2.0-or-later WITH cryptsetup-OpenSSL-exception"}}),

		Entry("a license after WITH is free text",
			cdx.Licenses{{License: &cdx.License{ID: "MIT WITH Apache-2.0"}}},
			&cdx.Licenses{{License: &cdx.License{Name: "MIT WITH Apache-2.0"}}}),

		Entry("an exception in place of a license is free text",
			cdx.Licenses{{License: &cdx.License{ID: "LLVM-exception OR MIT"}}},
			&cdx.Licenses{{License: &cdx.License{Name: "LLVM-exception OR MIT"}}}),

		Entry("an expression with parentheses and an or-later suffix",
			cdx.Licenses{{License: &cdx.License{ID: "(LGPL-2.1+ OR MIT) AND BSD-3-Clause"}}},
			&cdx.Licenses{{Expression: "(LGPL-2.1+ OR MIT) AND BSD-3-Clause"}}),

		Entry("an expression with a license reference",
			cdx.Licenses{{License: &cdx.License{ID: "MIT AND LicenseRef-Proprietary-1.0"}}},
			&cdx.Licenses{{Expression: "MIT AND LicenseRef-Proprietary-1.0"}}),

		Entry("free text in license.id becomes license.name",
			cdx.Licenses{{License: &cdx.License{ID: "GPLv3"}}},
			&cdx.Licenses{{License: &cdx.License{Name: "GPLv3"}}}),

		Entry("a slash-separated list is not SPDX and becomes license.name as is",
			cdx.Licenses{{License: &cdx.License{ID: "MIT/Apache-2.0"}}},
			&cdx.Licenses{{License: &cdx.License{Name: "MIT/Apache-2.0"}}}),

		Entry("an expression with an unknown identifier is free text",
			cdx.Licenses{{License: &cdx.License{ID: "GPL2 OR LGPL-2.1"}}},
			&cdx.Licenses{{License: &cdx.License{Name: "GPL2 OR LGPL-2.1"}}}),

		Entry("lower-case operators are free text",
			cdx.Licenses{{License: &cdx.License{ID: "MIT or Apache-2.0"}}},
			&cdx.Licenses{{License: &cdx.License{Name: "MIT or Apache-2.0"}}}),

		Entry("an unbalanced expression is free text",
			cdx.Licenses{{License: &cdx.License{ID: "(MIT OR Apache-2.0"}}},
			&cdx.Licenses{{License: &cdx.License{Name: "(MIT OR Apache-2.0"}}}),

		Entry("the rest of a license moved to license.name is kept",
			cdx.Licenses{{License: &cdx.License{ID: "GPLv3", URL: "https://example.com/COPYING"}}},
			&cdx.Licenses{{License: &cdx.License{Name: "GPLv3", URL: "https://example.com/COPYING"}}}),

		Entry("a named license is left alone",
			cdx.Licenses{{License: &cdx.License{Name: "Apache-2.0 OR MIT"}}},
			&cdx.Licenses{{License: &cdx.License{Name: "Apache-2.0 OR MIT"}}}),

		Entry("a lone expression is left alone",
			cdx.Licenses{{Expression: "MIT OR Apache-2.0"}},
			&cdx.Licenses{{Expression: "MIT OR Apache-2.0"}}),

		Entry("several SPDX ids stay a list",
			cdx.Licenses{{License: &cdx.License{ID: "MIT"}}, {License: &cdx.License{ID: "Apache-2.0"}}},
			&cdx.Licenses{{License: &cdx.License{ID: "MIT"}}, {License: &cdx.License{ID: "Apache-2.0"}}}),

		Entry("an id next to an expression joins it with AND",
			cdx.Licenses{{License: &cdx.License{ID: "MIT"}}, {Expression: "GPL-2.0-only OR BSD-2-Clause"}},
			&cdx.Licenses{{Expression: "MIT AND (GPL-2.0-only OR BSD-2-Clause)"}}),

		Entry("several expressions join with AND",
			cdx.Licenses{{Expression: "MIT OR Apache-2.0"}, {License: &cdx.License{ID: "GPL-2.0-only WITH Classpath-exception-2.0"}}},
			&cdx.Licenses{{Expression: "(MIT OR Apache-2.0) AND (GPL-2.0-only WITH Classpath-exception-2.0)"}}),

		Entry("duplicate expressions collapse",
			cdx.Licenses{{Expression: "MIT OR Apache-2.0"}, {License: &cdx.License{ID: "MIT OR Apache-2.0"}}},
			&cdx.Licenses{{Expression: "MIT OR Apache-2.0"}}),

		Entry("a named license next to an expression turns the expression into a name",
			cdx.Licenses{{License: &cdx.License{Name: "GPLv3"}}, {Expression: "MIT OR Apache-2.0"}},
			&cdx.Licenses{{License: &cdx.License{Name: "GPLv3"}}, {License: &cdx.License{Name: "MIT OR Apache-2.0"}}}),

		Entry("an empty list becomes nil",
			cdx.Licenses{},
			nil),
	)

	It("is idempotent", func() {
		in := cdx.Licenses{{License: &cdx.License{ID: "MIT"}}, {License: &cdx.License{ID: "Apache-2.0 OR GPL-2.0-only"}}, {License: &cdx.License{ID: "GPLv3"}}}
		once := normalizeLicenses(&in)
		Expect(normalizeLicenses(once)).To(Equal(once))
	})

	It("normalizes nested components, the metadata component and services", func() {
		bom := NewBOM()
		bom.Metadata = &cdx.Metadata{
			Component: &cdx.Component{Type: cdx.ComponentTypeContainer, Name: "img", Licenses: &cdx.Licenses{{License: &cdx.License{ID: "MIT OR Apache-2.0"}}}},
			Licenses:  &cdx.Licenses{{License: &cdx.License{ID: "MIT OR Apache-2.0"}}},
		}
		bom.Components = &[]cdx.Component{{
			Type: cdx.ComponentTypeLibrary, Name: "outer",
			Evidence:   &cdx.Evidence{Licenses: &cdx.Licenses{{License: &cdx.License{ID: "MIT OR Apache-2.0"}}}},
			Components: &[]cdx.Component{{Type: cdx.ComponentTypeLibrary, Name: "inner", Licenses: &cdx.Licenses{{License: &cdx.License{ID: "MIT OR Apache-2.0"}}}}},
		}}
		bom.Services = &[]cdx.Service{{Name: "svc", Licenses: &cdx.Licenses{{License: &cdx.License{ID: "MIT OR Apache-2.0"}}}}}

		Canonicalize(GinkgoT().Context(), bom)

		expected := &cdx.Licenses{{Expression: "MIT OR Apache-2.0"}}
		Expect(bom.Metadata.Component.Licenses).To(Equal(expected))
		Expect(bom.Metadata.Licenses).To(Equal(expected))
		Expect((*bom.Components)[0].Evidence.Licenses).To(Equal(expected))
		Expect((*(*bom.Components)[0].Components)[0].Licenses).To(Equal(expected))
		Expect((*bom.Services)[0].Licenses).To(Equal(expected))

		data, err := ToJSON(bom)
		Expect(err).NotTo(HaveOccurred())
		Expect(ValidateCycloneDX16Schema(data)).To(Succeed())
	})
})

var _ = Describe("normalizeLicenses in a merge", func() {
	It("normalizes the document license of the merged result", func(ctx SpecContext) {
		target := NewBOM()
		target.Metadata = &cdx.Metadata{Licenses: &cdx.Licenses{{License: &cdx.License{ID: "MIT OR Apache-2.0"}}}}
		target.Components = &[]cdx.Component{{BOMRef: "a", Type: cdx.ComponentTypeLibrary, Name: "a"}}

		for _, isolate := range []bool{false, true} {
			result, err := MergeBOMs(ctx, target, MergeOpts{ImportBOMs: []*cdx.BOM{NewBOM()}, PreserveBOMRefs: true, IsolateComponents: isolate})
			Expect(err).NotTo(HaveOccurred())
			Expect(result.Metadata.Licenses).To(Equal(&cdx.Licenses{{Expression: "MIT OR Apache-2.0"}}), "IsolateComponents=%v", isolate)

			data, err := ToJSON(result)
			Expect(err).NotTo(HaveOccurred())
			Expect(ValidateCycloneDX16Schema(data)).To(Succeed())
		}
	})
})
