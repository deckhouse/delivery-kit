package cyclonedxutil

import (
	cdx "github.com/CycloneDX/cyclonedx-go"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("DropSyftSourceFileComponents", func() {
	comps := func(cs ...cdx.Component) *cdx.BOM {
		list := append([]cdx.Component{}, cs...)
		return &cdx.BOM{Components: &list}
	}

	names := func(bom *cdx.BOM) []string {
		if bom.Components == nil {
			return nil
		}
		out := make([]string, 0, len(*bom.Components))
		for _, c := range *bom.Components {
			out = append(out, c.Name)
		}
		return out
	}

	It("drops PURL-less type=file components a dir scan emits for the manifest files", func() {
		bom := comps(
			cdx.Component{Type: cdx.ComponentTypeFile, Name: "go.mod"},
			cdx.Component{Type: cdx.ComponentTypeLibrary, Name: "github.com/samber/lo", PackageURL: "pkg:golang/github.com/samber/lo@v1.47.0"},
		)

		DropSyftSourceFileComponents(bom)

		Expect(names(bom)).To(Equal([]string{"github.com/samber/lo"}))
	})

	It("keeps a type=file component that carries a PackageURL", func() {
		bom := comps(
			cdx.Component{Type: cdx.ComponentTypeFile, Name: "some-artifact", PackageURL: "pkg:generic/some-artifact"},
		)

		DropSyftSourceFileComponents(bom)

		Expect(names(bom)).To(Equal([]string{"some-artifact"}))
	})

	It("nils out Components when only source file entries remain", func() {
		bom := comps(cdx.Component{Type: cdx.ComponentTypeFile, Name: "go.mod"})

		DropSyftSourceFileComponents(bom)

		Expect(bom.Components).To(BeNil())
	})

	It("is a no-op on a nil BOM or nil component list", func() {
		Expect(func() { DropSyftSourceFileComponents(nil) }).ToNot(Panic())
		Expect(func() { DropSyftSourceFileComponents(&cdx.BOM{}) }).ToNot(Panic())
	})
})
