package os_pm

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("ConvertToCycloneDX bom-ref (AI)", func() {
	It("should set a non-empty bom-ref equal to the purl for every component", func() {
		pkgs, err := ParsePmInstalledJSON(examplePmInstalledJSON)
		Expect(err).To(Succeed())

		bom := ConvertToCycloneDX(pkgs)
		Expect(bom).ToNot(BeNil())

		for _, comp := range *bom.Components {
			Expect(comp.BOMRef).ToNot(BeEmpty(), "component %s should have bom-ref", comp.Name)
			Expect(comp.BOMRef).To(Equal(comp.PackageURL), "component %s bom-ref should equal purl", comp.Name)
		}
	})

	It("should produce unique bom-refs across components", func() {
		pkgs, err := ParsePmInstalledJSON(examplePmInstalledJSON)
		Expect(err).To(Succeed())

		bom := ConvertToCycloneDX(pkgs)
		Expect(bom).ToNot(BeNil())

		seen := map[string]struct{}{}
		for _, comp := range *bom.Components {
			_, dup := seen[comp.BOMRef]
			Expect(dup).To(BeFalse(), "bom-ref %s must be unique", comp.BOMRef)
			seen[comp.BOMRef] = struct{}{}
		}
	})
})
