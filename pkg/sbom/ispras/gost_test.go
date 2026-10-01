package ispras

import (
	cdx "github.com/CycloneDX/cyclonedx-go"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/samber/lo"

	"github.com/werf/werf/v3/pkg/sbom/cyclonedxutil/gost"
)

var _ = Describe("aggregateGOST", func() {
	withGOST := func(name string, attack, security gost.GostValue, children ...cdx.Component) cdx.Component {
		comp := cdx.Component{Name: name}
		gost.SetComponent(&comp, gost.Config{AttackSurface: attack, SecurityFunction: security})
		if len(children) > 0 {
			comp.Components = &children
		}
		return comp
	}

	DescribeTable("takes the maximum over all descendants",
		func(ctx SpecContext, components []cdx.Component, expected GOSTValues) {
			Expect(aggregateGOST(ctx, components)).To(Equal(expected))
		},
		Entry("empty", nil, GOSTValues{}),
		Entry("flat list",
			[]cdx.Component{
				withGOST("a", gost.GostValueNo, gost.GostValueYes),
				withGOST("b", gost.GostValueIndirect, gost.GostValueNo),
			},
			GOSTValues{AttackSurface: gost.GostValueIndirect, SecurityFunction: gost.GostValueYes}),
		Entry("higher value only in a grandchild",
			[]cdx.Component{
				withGOST("parent", gost.GostValueNo, gost.GostValueNo,
					withGOST("child", gost.GostValueIndirect, gost.GostValueNo,
						withGOST("grandchild", gost.GostValueYes, gost.GostValueYes),
					),
				),
			},
			GOSTValues{AttackSurface: gost.GostValueYes, SecurityFunction: gost.GostValueYes}),
		Entry("fields are aggregated independently",
			[]cdx.Component{
				withGOST("parent", gost.GostValueYes, gost.GostValueNo,
					withGOST("child", gost.GostValueNo, gost.GostValueYes),
				),
			},
			GOSTValues{AttackSurface: gost.GostValueYes, SecurityFunction: gost.GostValueYes}),
	)
})

var _ = Describe("Gost source languages aggregation", func() {
	It("aggregates the languages of the image components", func(ctx SpecContext) {
		img := imageSBOM("backend", componentWithLangs("a", "Go"), componentWithLangs("b", "Python"), componentWithLangs("c", ""))

		Expect(aggregateSourceLangs(ctx, []*ImageSBOM{img})).To(Equal([]string{"Go", "Python"}))
	})

	It("sets the union of the image languages on the container component", func(ctx SpecContext) {
		bom, err := (&ContainerAssembler{}).Assemble(
			ctx,
			[]*ImageSBOM{imageSBOM("backend", componentWithLangs("a", "Go"), componentWithLangs("b", "Python"))},
			ProductMeta{AppName: "product", AppVersion: "1.0"},
		)
		Expect(err).To(Succeed())

		containers := *bom.Components
		Expect(containers).To(HaveLen(1))
		Expect(gost.GetComponentSourceLangs(ctx, &containers[0])).To(Equal([]string{"Go", "Python"}))
	})

	It("unions the image languages with the ones already set on the container component", func(ctx SpecContext) {
		img := imageSBOM("backend", componentWithLangs("a", "Go"))
		img.BOM.Properties = &[]cdx.Property{{Name: gost.PropertySourceLangs, Value: "Rust"}}

		bom, err := (&ContainerAssembler{}).Assemble(
			ctx,
			[]*ImageSBOM{img},
			ProductMeta{AppName: "product", AppVersion: "1.0"},
		)
		Expect(err).To(Succeed())

		containers := *bom.Components
		Expect(gost.GetComponentSourceLangs(ctx, &containers[0])).To(Equal([]string{"Go", "Rust"}))
	})

	It("keeps a single GOST:source_langs property when the image carries it on both the root component and the document", func(ctx SpecContext) {
		img := imageSBOM("backend", componentWithLangs("a", "Go"))
		img.BOM.Metadata = &cdx.Metadata{Component: &cdx.Component{
			Type:       cdx.ComponentTypeContainer,
			BOMRef:     "root",
			Name:       "backend",
			Properties: &[]cdx.Property{{Name: gost.PropertySourceLangs, Value: "Lua"}},
		}}
		img.BOM.Properties = &[]cdx.Property{{Name: gost.PropertySourceLangs, Value: "Rust"}}

		bom, err := (&ContainerAssembler{}).Assemble(
			ctx,
			[]*ImageSBOM{img},
			ProductMeta{AppName: "product", AppVersion: "1.0"},
		)
		Expect(err).To(Succeed())

		containers := *bom.Components
		Expect(containers).To(HaveLen(1))
		langProps := lo.Filter(lo.FromPtr(containers[0].Properties), func(p cdx.Property, _ int) bool {
			return p.Name == gost.PropertySourceLangs
		})
		Expect(langProps).To(Equal([]cdx.Property{{Name: gost.PropertySourceLangs, Value: "Go,Lua,Rust"}}))
		Expect(gost.GetComponentSourceLangs(ctx, bom.Metadata.Component)).To(Equal([]string{"Go", "Lua", "Rust"}))
	})

	DescribeTable("includes the languages of components nested under the image root component in the product union",
		func(ctx SpecContext, assembler Assembler) {
			img := imageSBOM("backend", componentWithLangs("a", "Go"))
			img.BOM.Metadata = &cdx.Metadata{Component: &cdx.Component{
				Type:       cdx.ComponentTypeContainer,
				BOMRef:     "root",
				Name:       "backend",
				Components: &[]cdx.Component{componentWithLangs("nested", "Lua")},
			}}

			bom, err := assembler.Assemble(
				ctx,
				[]*ImageSBOM{img},
				ProductMeta{AppName: "product", AppVersion: "1.0"},
			)
			Expect(err).To(Succeed())

			Expect(gost.GetComponentSourceLangs(ctx, bom.Metadata.Component)).To(Equal([]string{"Go", "Lua"}))
		},
		Entry("container format", &ContainerAssembler{}),
		Entry("oss format", &OSSAssembler{}),
	)

	DescribeTable("includes the BOM-level languages of an image in the product union",
		func(ctx SpecContext, assembler Assembler) {
			img := imageSBOM("backend", componentWithLangs("a", "Go"))
			img.BOM.Properties = &[]cdx.Property{{Name: gost.PropertySourceLangs, Value: "Rust"}}

			bom, err := assembler.Assemble(
				ctx,
				[]*ImageSBOM{img},
				ProductMeta{AppName: "product", AppVersion: "1.0"},
			)
			Expect(err).To(Succeed())

			Expect(gost.GetComponentSourceLangs(ctx, bom.Metadata.Component)).To(Equal([]string{"Go", "Rust"}))
		},
		Entry("container format", &ContainerAssembler{}),
		Entry("oss format", &OSSAssembler{}),
	)

	DescribeTable("sets the union of all image languages on the product component",
		func(ctx SpecContext, assembler Assembler) {
			bom, err := assembler.Assemble(
				ctx,
				[]*ImageSBOM{
					imageSBOM("backend", componentWithLangs("a", "Go")),
					imageSBOM("frontend", componentWithLangs("b", "JavaScript"), componentWithLangs("c", "Go")),
				},
				ProductMeta{AppName: "product", AppVersion: "1.0"},
			)
			Expect(err).To(Succeed())

			Expect(gost.GetComponentSourceLangs(ctx, bom.Metadata.Component)).To(Equal([]string{"Go", "JavaScript"}))
		},
		Entry("container format", &ContainerAssembler{}),
		Entry("oss format", &OSSAssembler{}),
	)
})
