package gost

import (
	cdx "github.com/CycloneDX/cyclonedx-go"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/samber/lo"
)

var _ = Describe("Gost source languages", func() {
	DescribeTable("SetComponentSourceLangs",
		func(comp *cdx.Component, langs []string, expectedProperties []cdx.Property) {
			SetComponentSourceLangs(comp, langs)
			Expect(lo.FromPtr(comp.Properties)).To(Equal(expectedProperties))
		},
		Entry("should add a single property with the languages joined",
			&cdx.Component{Name: "test"},
			[]string{"Go", "Python"},
			[]cdx.Property{{Name: PropertySourceLangs, Value: "Go, Python"}}),
		Entry("should skip empty and duplicate languages",
			&cdx.Component{Name: "test"},
			[]string{"Go", " ", "Go", "", "Python"},
			[]cdx.Property{{Name: PropertySourceLangs, Value: "Go, Python"}}),
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
	)

	DescribeTable("GetComponentSourceLangs",
		func(comp *cdx.Component, expected []string) {
			Expect(GetComponentSourceLangs(comp)).To(Equal(expected))
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
	)

	DescribeTable("CollectSourceLangs",
		func(components []cdx.Component, expected []string) {
			Expect(CollectSourceLangs(components)).To(Equal(expected))
		},
		Entry("should return nil for components without languages",
			[]cdx.Component{{Name: "test"}}, nil),
		Entry("should union languages in order of first appearance",
			[]cdx.Component{
				{Name: "a", Properties: &[]cdx.Property{{Name: PropertySourceLangs, Value: "Python"}}},
				{Name: "b", Properties: &[]cdx.Property{{Name: PropertySourceLangs, Value: "Go, Python"}}},
			},
			[]string{"Python", "Go"}),
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

	It("should not be affected by an Upsert of the other GOST properties", func() {
		comp := cdx.Component{Name: "test"}
		SetComponentSourceLangs(&comp, []string{"Go"})

		bom := &cdx.BOM{Components: &[]cdx.Component{comp}}
		Expect(Upsert(bom, Config{AttackSurface: GostValueYes, SecurityFunction: GostValueNo})).To(Succeed())

		Expect(GetComponentSourceLangs(&(*bom.Components)[0])).To(Equal([]string{"Go"}))
	})
})
