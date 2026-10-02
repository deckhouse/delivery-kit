package gost

import (
	cdx "github.com/CycloneDX/cyclonedx-go"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/samber/lo"
)

var _ = Describe("Gost source languages", func() {
	DescribeTable("SetComponentSourceLangs",
		func(ctx SpecContext, comp *cdx.Component, langs []string, expectedProperties []cdx.Property) {
			SetComponentSourceLangs(ctx, comp, langs)
			Expect(lo.FromPtr(comp.Properties)).To(Equal(expectedProperties))
		},
		Entry("should add a single property with the languages joined",
			&cdx.Component{Name: "test"},
			[]string{"Go", "Python"},
			[]cdx.Property{{Name: PropertySourceLangs, Value: "Go,Python"}}),
		Entry("should skip empty and duplicate languages",
			&cdx.Component{Name: "test"},
			[]string{"Go", " ", "Go", "", "Python"},
			[]cdx.Property{{Name: PropertySourceLangs, Value: "Go,Python"}}),
		Entry("should keep the component untouched when no language is given",
			&cdx.Component{Name: "test"},
			[]string{""},
			nil),
		Entry("should update an existing property instead of adding a second one",
			&cdx.Component{
				Name:       "test",
				Properties: &[]cdx.Property{{Name: PropertySourceLangs, Value: "Go"}},
			},
			[]string{"Rust"},
			[]cdx.Property{{Name: PropertySourceLangs, Value: "Rust"}}),
		Entry("should fold repeated properties into the first one and keep the others in place",
			&cdx.Component{
				Name: "test",
				Properties: &[]cdx.Property{
					{Name: "other", Value: "1"},
					{Name: PropertySourceLangs, Value: "Go"},
					{Name: "other", Value: "2"},
					{Name: PropertySourceLangs, Value: "Rust"},
				},
			},
			[]string{"Go", "Lua", "Rust"},
			[]cdx.Property{
				{Name: "other", Value: "1"},
				{Name: PropertySourceLangs, Value: "Go,Lua,Rust"},
				{Name: "other", Value: "2"},
			}),
	)

	DescribeTable("GetComponentSourceLangs",
		func(ctx SpecContext, comp *cdx.Component, expected []string) {
			Expect(GetComponentSourceLangs(ctx, comp)).To(Equal(expected))
		},
		Entry("should return nil when the property is missing",
			&cdx.Component{Name: "test"}, nil),
		Entry("should split the comma-separated value",
			&cdx.Component{
				Name:       "test",
				Properties: &[]cdx.Property{{Name: PropertySourceLangs, Value: "Go, Python"}},
			},
			[]string{"Go", "Python"}),
		Entry("should tolerate irregular separators",
			&cdx.Component{
				Name:       "test",
				Properties: &[]cdx.Property{{Name: PropertySourceLangs, Value: "Go,,  Rust ,"}},
			},
			[]string{"Go", "Rust"}),
		Entry("should union repeated properties of a non-canonical component",
			&cdx.Component{
				Name:       "test",
				Properties: &[]cdx.Property{{Name: PropertySourceLangs, Value: "Rust"}, {Name: PropertySourceLangs, Value: "Go"}},
			},
			[]string{"Go", "Rust"}),
	)

	DescribeTable("CollectSourceLangs",
		func(ctx SpecContext, components []cdx.Component, expected []string) {
			Expect(CollectSourceLangs(ctx, components)).To(Equal(expected))
		},
		Entry("should return nil for components without languages",
			[]cdx.Component{{Name: "test"}}, nil),
		Entry("should union languages sorted regardless of their order of appearance",
			[]cdx.Component{
				{Name: "a", Properties: &[]cdx.Property{{Name: PropertySourceLangs, Value: "Python"}}},
				{Name: "b", Properties: &[]cdx.Property{{Name: PropertySourceLangs, Value: "Go, Python"}}},
			},
			[]string{"Go", "Python"}),
		Entry("should include nested components",
			[]cdx.Component{
				{
					Name:       "container",
					Properties: &[]cdx.Property{{Name: PropertySourceLangs, Value: "Go"}},
					Components: &[]cdx.Component{
						{Name: "nested", Properties: &[]cdx.Property{{Name: PropertySourceLangs, Value: "Lua"}}},
					},
				},
			},
			[]string{"Go", "Lua"}),
	)

	DescribeTable("CollectBOMSourceLangs",
		func(ctx SpecContext, bom *cdx.BOM, expected []string) {
			Expect(CollectBOMSourceLangs(ctx, bom)).To(Equal(expected))
		},
		Entry("should return nil for an empty BOM", &cdx.BOM{}, nil),
		Entry("should union document properties, the root component and the component tree",
			&cdx.BOM{
				Properties: &[]cdx.Property{{Name: PropertySourceLangs, Value: "Rust"}},
				Metadata: &cdx.Metadata{Component: &cdx.Component{
					Name:       "root",
					Properties: &[]cdx.Property{{Name: PropertySourceLangs, Value: "Lua"}},
				}},
				Components: &[]cdx.Component{
					{Name: "a", Properties: &[]cdx.Property{{Name: PropertySourceLangs, Value: "Go, Rust"}}},
				},
			},
			[]string{"Go", "Lua", "Rust"}),
		Entry("should include components nested under the root component and repeated document properties",
			&cdx.BOM{
				Properties: &[]cdx.Property{{Name: PropertySourceLangs, Value: "Rust"}, {Name: PropertySourceLangs, Value: "C"}},
				Metadata: &cdx.Metadata{Component: &cdx.Component{
					Name:       "root",
					Components: &[]cdx.Component{{Name: "n", Properties: &[]cdx.Property{{Name: PropertySourceLangs, Value: "Lua"}}}},
				}},
			},
			[]string{"C", "Lua", "Rust"}),
	)

	DescribeTable("NormalizeSourceLangsValue",
		func(ctx SpecContext, raw, expected string) {
			Expect(NormalizeSourceLangsValue(ctx, raw)).To(Equal(expected))
		},
		Entry("should sort, deduplicate and trim", "Python, Go,Go", "Go,Python"),
		Entry("should keep a canonical value as is", "Go,Python", "Go,Python"),
		Entry("should turn a blank value into an empty one", " , ", ""),
	)

	DescribeTable("MergeSourceLangsValues",
		func(ctx SpecContext, a, b, expected string) {
			Expect(MergeSourceLangsValues(ctx, a, b)).To(Equal(expected))
		},
		Entry("should union two disjoint values", "C", "Assembly", "Assembly,C"),
		Entry("should drop duplicates across the two values", "C", "Assembly,C", "Assembly,C"),
		Entry("should tolerate an empty side", "", "Go", "Go"),
	)

	It("should not be affected by an Upsert of the other GOST properties", func(ctx SpecContext) {
		comp := cdx.Component{Name: "test"}
		SetComponentSourceLangs(ctx, &comp, []string{"Go"})

		bom := &cdx.BOM{Components: &[]cdx.Component{comp}}
		Expect(Upsert(bom, Config{AttackSurface: GostValueYes, SecurityFunction: GostValueNo})).To(Succeed())

		Expect(GetComponentSourceLangs(ctx, &(*bom.Components)[0])).To(Equal([]string{"Go"}))
	})
})
