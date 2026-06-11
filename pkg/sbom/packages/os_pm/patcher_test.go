package os_pm

import (
	cdx "github.com/CycloneDX/cyclonedx-go"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("BOMPatcher", func() {
	It("should return BOM unchanged when no packages configured", func(ctx SpecContext) {
		patcher := NewBOMPatcher("test-image:latest", false)
		originalBOM := &cdx.BOM{
			BOMFormat:   "CycloneDX",
			SpecVersion: cdx.SpecVersion1_6,
			Components: &[]cdx.Component{
				{Name: "existing-component", Version: "1.0.0"},
			},
		}

		result, err := patcher.Apply(ctx, originalBOM)
		Expect(err).To(Succeed())
		Expect(result).To(Equal(originalBOM))
	})

	It("should return BOM unchanged when imageRef is empty", func(ctx SpecContext) {
		patcher := NewBOMPatcher("", true)
		originalBOM := &cdx.BOM{
			BOMFormat:   "CycloneDX",
			SpecVersion: cdx.SpecVersion1_6,
		}

		result, err := patcher.Apply(ctx, originalBOM)
		Expect(err).To(Succeed())
		Expect(result).To(Equal(originalBOM))
	})
})
