package cyclonedxutil

import (
	cdx "github.com/CycloneDX/cyclonedx-go"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/samber/lo"
)

var _ = Describe("MarkWerfTool", func() {
	It("records werf next to the scanner and encodes", func() {
		bom := NewBOM()
		bom.Metadata = &cdx.Metadata{Tools: &cdx.ToolsChoice{Components: &[]cdx.Component{{Type: cdx.ComponentTypeApplication, Name: "syft", Version: "1.45.1"}}}}

		MarkWerfTool(bom, "v2.0.0")
		MarkWerfTool(bom, "v2.0.0")

		Expect(HasWerfTool(bom)).To(BeTrue())
		Expect(lo.Map(*bom.Metadata.Tools.Components, func(c cdx.Component, _ int) string { return c.Name })).To(Equal([]string{"syft", "werf"}))
		_, err := ToJSON(bom)
		Expect(err).NotTo(HaveOccurred())
	})

	It("converts tools recorded in the legacy array form before adding werf", func() {
		hashes := &[]cdx.Hash{{Algorithm: cdx.HashAlgoSHA256, Value: "ab"}}
		bom := NewBOM()
		bom.Metadata = &cdx.Metadata{Tools: &cdx.ToolsChoice{Tools: &[]cdx.Tool{{Vendor: "anchore", Name: "syft", Version: "0.90.0", Hashes: hashes}}}}

		MarkWerfTool(bom, "v2.0.0")

		Expect(bom.Metadata.Tools.Tools).To(BeNil())
		Expect(*bom.Metadata.Tools.Components).To(Equal([]cdx.Component{
			{Type: cdx.ComponentTypeApplication, Manufacturer: &cdx.OrganizationalEntity{Name: "anchore"}, Name: "syft", Version: "0.90.0", Hashes: hashes},
			{Type: cdx.ComponentTypeApplication, Name: "werf", Version: "v2.0.0"},
		}))
		_, err := ToJSON(bom)
		Expect(err).NotTo(HaveOccurred())
	})

	It("allocates metadata and tools when the BOM has none", func() {
		bom := NewBOM()

		MarkWerfTool(bom, "v2.0.0")

		Expect(HasWerfTool(bom)).To(BeTrue())
	})
})

var _ = Describe("HasWerfTool", func() {
	It("reads the legacy array form", func() {
		bom := &cdx.BOM{Metadata: &cdx.Metadata{Tools: &cdx.ToolsChoice{Tools: &[]cdx.Tool{{Name: "werf", Version: "v1"}}}}}
		Expect(HasWerfTool(bom)).To(BeTrue())
	})

	It("is false without tools or for other producers", func() {
		Expect(HasWerfTool(nil)).To(BeFalse())
		Expect(HasWerfTool(&cdx.BOM{})).To(BeFalse())
		Expect(HasWerfTool(&cdx.BOM{Metadata: &cdx.Metadata{Tools: &cdx.ToolsChoice{Components: &[]cdx.Component{{Name: "trivy"}}}}})).To(BeFalse())
	})
})
