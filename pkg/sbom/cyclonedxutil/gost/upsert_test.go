package gost

import (
	cdx "github.com/CycloneDX/cyclonedx-go"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/samber/lo"
)

var _ = Describe("Gost SBOM setter", func() {
	DescribeTable("Set",
		func(bom *cdx.BOM, config Config, expectedComponents []cdx.Component, expectedErrMatcher OmegaMatcher) {
			err := Upsert(bom, config)
			Expect(err).To(expectedErrMatcher)
			if err != nil {
				return
			}
			if bom.Components != nil {
				Expect(lo.FromPtr(bom.Components)).To(Equal(expectedComponents))
			}
			if bom.Metadata != nil && bom.Metadata.Component != nil {
				Expect(lo.FromPtr(bom.Metadata.Component.Components)).To(Equal(expectedComponents))
			}
		},
		Entry("should fail if BOM is nil",
			nil, Config{}, nil, MatchError("BOM is required")),
		Entry("should add GOST properties if missing",
			&cdx.BOM{
				Components: &[]cdx.Component{{Name: "test"}},
			},
			Config{AttackSurface: GostValueYes, SecurityFunction: GostValueNo},
			[]cdx.Component{
				{
					Name: "test",
					Properties: &[]cdx.Property{
						{Name: PropertyAttackSurface, Value: "yes"},
						{Name: PropertySecurityFunction, Value: "no"},
					},
				},
			},
			Succeed()),
		Entry("should update existing GOST properties",
			&cdx.BOM{
				Components: &[]cdx.Component{
					{
						Name: "test",
						Properties: &[]cdx.Property{
							{Name: PropertyAttackSurface, Value: "no"},
							{Name: PropertySecurityFunction, Value: "no"},
						},
					},
				},
			},
			Config{AttackSurface: GostValueYes, SecurityFunction: GostValueYes},
			[]cdx.Component{
				{
					Name: "test",
					Properties: &[]cdx.Property{
						{Name: PropertyAttackSurface, Value: "yes"},
						{Name: PropertySecurityFunction, Value: "yes"},
					},
				},
			},
			Succeed()),
		Entry("should ignore undefined values in config during update",
			&cdx.BOM{
				Components: &[]cdx.Component{
					{
						Name: "test",
						Properties: &[]cdx.Property{
							{Name: PropertyAttackSurface, Value: "no"},
						},
					},
				},
			},
			Config{AttackSurface: GostValueUndefined, SecurityFunction: GostValueYes},
			[]cdx.Component{
				{
					Name: "test",
					Properties: &[]cdx.Property{
						{Name: PropertyAttackSurface, Value: "no"},
						{Name: PropertySecurityFunction, Value: "yes"},
					},
				},
			},
			Succeed()),
		Entry("should set GOST properties on nested components",
			&cdx.BOM{
				Components: &[]cdx.Component{{
					Name: "parent",
					Components: &[]cdx.Component{{
						Name:       "child",
						Components: &[]cdx.Component{{Name: "grandchild"}},
					}},
				}},
			},
			Config{AttackSurface: GostValueYes, SecurityFunction: GostValueNo},
			[]cdx.Component{{
				Name: "parent",
				Properties: &[]cdx.Property{
					{Name: PropertyAttackSurface, Value: "yes"},
					{Name: PropertySecurityFunction, Value: "no"},
				},
				Components: &[]cdx.Component{{
					Name: "child",
					Properties: &[]cdx.Property{
						{Name: PropertyAttackSurface, Value: "yes"},
						{Name: PropertySecurityFunction, Value: "no"},
					},
					Components: &[]cdx.Component{{
						Name: "grandchild",
						Properties: &[]cdx.Property{
							{Name: PropertyAttackSurface, Value: "yes"},
							{Name: PropertySecurityFunction, Value: "no"},
						},
					}},
				}},
			}},
			Succeed()),
		Entry("should set GOST properties on components nested under the metadata component",
			&cdx.BOM{
				Metadata: &cdx.Metadata{
					Component: &cdx.Component{
						Name:       "root",
						Components: &[]cdx.Component{{Name: "root-child"}},
					},
				},
			},
			Config{AttackSurface: GostValueNo, SecurityFunction: GostValueYes},
			[]cdx.Component{{
				Name: "root-child",
				Properties: &[]cdx.Property{
					{Name: PropertyAttackSurface, Value: "no"},
					{Name: PropertySecurityFunction, Value: "yes"},
				},
			}},
			Succeed()),
		Entry("should inject 'indirect' value",
			&cdx.BOM{
				Components: &[]cdx.Component{{Name: "test"}},
			},
			Config{AttackSurface: GostValueIndirect, SecurityFunction: GostValueIndirect},
			[]cdx.Component{
				{
					Name: "test",
					Properties: &[]cdx.Property{
						{Name: PropertyAttackSurface, Value: "indirect"},
						{Name: PropertySecurityFunction, Value: "indirect"},
					},
				},
			},
			Succeed()),
	)

	DescribeTable("attack surface follows the dependency tree",
		func(bom *cdx.BOM, config Config, expected map[string]GostValue) {
			Expect(Upsert(bom, config)).To(Succeed())

			actual := map[string]GostValue{}
			for i := range lo.FromPtr(bom.Components) {
				comp := &(*bom.Components)[i]
				actual[comp.BOMRef] = GetComponent(comp).AttackSurface
			}

			Expect(actual).To(Equal(expected))
		},
		Entry("yes reaches only what nothing else depends on",
			&cdx.BOM{
				Components: &[]cdx.Component{{BOMRef: "curl"}, {BOMRef: "openssl"}, {BOMRef: "libc"}, {BOMRef: "jq"}},
				Dependencies: &[]cdx.Dependency{
					{Ref: "curl", Dependencies: &[]string{"openssl"}},
					{Ref: "openssl", Dependencies: &[]string{"libc"}},
				},
			},
			Config{AttackSurface: GostValueYes, SecurityFunction: GostValueYes},
			map[string]GostValue{
				"curl":    GostValueYes,
				"jq":      GostValueYes,
				"openssl": GostValueIndirect,
				"libc":    GostValueIndirect,
			}),
		Entry("a self-referencing entry does not demote its own subject",
			&cdx.BOM{
				Components:   &[]cdx.Component{{BOMRef: "curl"}},
				Dependencies: &[]cdx.Dependency{{Ref: "curl", Dependencies: &[]string{"curl"}}},
			},
			Config{AttackSurface: GostValueYes, SecurityFunction: GostValueYes},
			map[string]GostValue{"curl": GostValueYes}),
		Entry("no dependency tree makes every component a root",
			&cdx.BOM{
				Components: &[]cdx.Component{{BOMRef: "a"}, {BOMRef: "b"}},
			},
			Config{AttackSurface: GostValueYes, SecurityFunction: GostValueYes},
			map[string]GostValue{"a": GostValueYes, "b": GostValueYes}),
		Entry("indirect applies to the whole tree, roots included",
			&cdx.BOM{
				Components:   &[]cdx.Component{{BOMRef: "curl"}, {BOMRef: "openssl"}},
				Dependencies: &[]cdx.Dependency{{Ref: "curl", Dependencies: &[]string{"openssl"}}},
			},
			Config{AttackSurface: GostValueIndirect, SecurityFunction: GostValueNo},
			map[string]GostValue{"curl": GostValueIndirect, "openssl": GostValueIndirect}),
		Entry("no applies to the whole tree, roots included",
			&cdx.BOM{
				Components:   &[]cdx.Component{{BOMRef: "curl"}, {BOMRef: "openssl"}},
				Dependencies: &[]cdx.Dependency{{Ref: "curl", Dependencies: &[]string{"openssl"}}},
			},
			Config{AttackSurface: GostValueNo, SecurityFunction: GostValueNo},
			map[string]GostValue{"curl": GostValueNo, "openssl": GostValueNo}),
	)

	It("keeps the image root at the configured value while its packages are demoted", func() {
		bom := &cdx.BOM{
			Metadata:     &cdx.Metadata{Component: &cdx.Component{BOMRef: "image", Name: "image"}},
			Components:   &[]cdx.Component{{BOMRef: "curl"}, {BOMRef: "openssl"}},
			Dependencies: &[]cdx.Dependency{{Ref: "curl", Dependencies: &[]string{"openssl"}}},
		}

		Expect(Upsert(bom, Config{AttackSurface: GostValueYes, SecurityFunction: GostValueYes})).To(Succeed())

		Expect(GetComponent(bom.Metadata.Component).AttackSurface).To(Equal(GostValueYes))
		Expect(GetComponent(&(*bom.Components)[1]).AttackSurface).To(Equal(GostValueIndirect))
	})

	It("demotes a nested component the tree depends on", func() {
		bom := &cdx.BOM{
			Components: &[]cdx.Component{{
				BOMRef:     "parent",
				Components: &[]cdx.Component{{BOMRef: "nested"}, {BOMRef: "nested-root"}},
			}},
			Dependencies: &[]cdx.Dependency{{Ref: "parent", Dependencies: &[]string{"nested"}}},
		}

		Expect(Upsert(bom, Config{AttackSurface: GostValueYes, SecurityFunction: GostValueYes})).To(Succeed())

		nested := lo.FromPtr((*bom.Components)[0].Components)
		Expect(GetComponent(&nested[0]).AttackSurface).To(Equal(GostValueIndirect))
		Expect(GetComponent(&nested[1]).AttackSurface).To(Equal(GostValueYes))
	})
})
