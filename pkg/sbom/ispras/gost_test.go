package ispras

import (
	"context"

	cdx "github.com/CycloneDX/cyclonedx-go"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/werf/werf/v2/pkg/sbom/cyclonedxutil/gost"
)

func componentWithLangs(name, langs string) cdx.Component {
	comp := cdx.Component{
		Type:       cdx.ComponentTypeLibrary,
		BOMRef:     name,
		Name:       name,
		Properties: &[]cdx.Property{{Name: gost.PropertyAttackSurface, Value: gost.GostValueYes.String()}},
	}
	if langs != "" {
		*comp.Properties = append(*comp.Properties, cdx.Property{Name: gost.PropertySourceLangs, Value: langs})
	}

	return comp
}

func imageSBOM(name string, components ...cdx.Component) *ImageSBOM {
	return NewImageSBOM(name, &cdx.BOM{
		BOMFormat:   "CycloneDX",
		SpecVersion: cdx.SpecVersion1_6,
		Components:  &components,
	})
}

var _ = Describe("Gost source languages aggregation", func() {
	It("aggregates the languages of the image components", func() {
		img := imageSBOM("backend", componentWithLangs("a", "Go"), componentWithLangs("b", "Python"), componentWithLangs("c", ""))

		Expect(img.GOST.SourceLangs).To(Equal([]string{"Go", "Python"}))
	})

	It("sets the union of the image languages on the container component", func() {
		bom, err := (&ContainerAssembler{}).Assemble(
			context.Background(),
			[]*ImageSBOM{imageSBOM("backend", componentWithLangs("a", "Go"), componentWithLangs("b", "Python"))},
			ProductMeta{AppName: "product", AppVersion: "1.0"},
		)
		Expect(err).To(Succeed())

		containers := *bom.Components
		Expect(containers).To(HaveLen(1))
		Expect(gost.GetComponentSourceLangs(&containers[0])).To(Equal([]string{"Go", "Python"}))
	})

	It("unions the image languages with the ones already set on the container component", func() {
		img := imageSBOM("backend", componentWithLangs("a", "Go"))
		img.BOM.Properties = &[]cdx.Property{{Name: gost.PropertySourceLangs, Value: "Rust"}}

		bom, err := (&ContainerAssembler{}).Assemble(
			context.Background(),
			[]*ImageSBOM{img},
			ProductMeta{AppName: "product", AppVersion: "1.0"},
		)
		Expect(err).To(Succeed())

		containers := *bom.Components
		Expect(gost.GetComponentSourceLangs(&containers[0])).To(Equal([]string{"Rust", "Go"}))
	})

	DescribeTable("sets the union of all image languages on the product component",
		func(assembler Assembler) {
			bom, err := assembler.Assemble(
				context.Background(),
				[]*ImageSBOM{
					imageSBOM("backend", componentWithLangs("a", "Go")),
					imageSBOM("frontend", componentWithLangs("b", "JavaScript"), componentWithLangs("c", "Go")),
				},
				ProductMeta{AppName: "product", AppVersion: "1.0"},
			)
			Expect(err).To(Succeed())

			Expect(gost.GetComponentSourceLangs(bom.Metadata.Component)).To(Equal([]string{"Go", "JavaScript"}))
		},
		Entry("container format", &ContainerAssembler{}),
		Entry("oss format", &OSSAssembler{}),
	)
})
