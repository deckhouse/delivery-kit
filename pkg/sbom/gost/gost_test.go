package gost

import (
	cdx "github.com/CycloneDX/cyclonedx-go"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/samber/lo"
)

var _ = Describe("Gost SBOM properties", func() {
	DescribeTable("Validate",
		func(bom *cdx.BOM, expectedErrMatcher OmegaMatcher) {
			err := Validate(bom)
			Expect(err).To(expectedErrMatcher)
		},
		Entry("should fail if BOM is nil",
			nil,
			MatchError("BOM is required")),
		Entry("should fail if SpecVersion is not 1.6",
			&cdx.BOM{SpecVersion: cdx.SpecVersion1_5},
			MatchError(ContainSubstring("requires CycloneDX version 1.6"))),
		Entry("should fail if GOST properties are missing in metadata component",
			&cdx.BOM{
				SpecVersion: cdx.SpecVersion1_6,
				Metadata: &cdx.Metadata{
					Component: &cdx.Component{Name: "test"},
				},
			},
			MatchError(ContainSubstring("missing mandatory GOST properties"))),
		Entry("should fail if GOST properties are missing in components",
			&cdx.BOM{
				SpecVersion: cdx.SpecVersion1_6,
				Components: &[]cdx.Component{
					{Name: "test-comp"},
				},
			},
			MatchError(ContainSubstring("missing mandatory GOST properties"))),
		Entry("should fail if GOST properties have invalid values",
			&cdx.BOM{
				SpecVersion: cdx.SpecVersion1_6,
				Components: &[]cdx.Component{
					{
						Name: "test-comp",
						Properties: &[]cdx.Property{
							{Name: PropertyAttackSurface, Value: "invalid"},
							{Name: PropertySecurityFunction, Value: "yes"},
						},
					},
				},
			},
			MatchError(ContainSubstring("invalid value for GOST:attack_surface"))),
		Entry("should succeed if GOST properties are present and valid (yes/no)",
			&cdx.BOM{
				SpecVersion: cdx.SpecVersion1_6,
				Components: &[]cdx.Component{
					{
						Name: "test-comp",
						Properties: &[]cdx.Property{
							{Name: PropertyAttackSurface, Value: "yes"},
							{Name: PropertySecurityFunction, Value: "no"},
						},
					},
				},
			},
			Succeed()),
		Entry("should succeed if GOST properties are present and valid (inherit)",
			&cdx.BOM{
				SpecVersion: cdx.SpecVersion1_6,
				Components: &[]cdx.Component{
					{
						Name: "test-comp",
						Properties: &[]cdx.Property{
							{Name: PropertyAttackSurface, Value: "inherit"},
							{Name: PropertySecurityFunction, Value: "inherit"},
						},
					},
				},
			},
			Succeed()),
	)

	DescribeTable("Inject",
		func(bom *cdx.BOM, config Config, expectedComponents []cdx.Component, expectedErrMatcher OmegaMatcher) {
			err := Inject(bom, config)
			Expect(err).To(expectedErrMatcher)
			if err != nil {
				return
			}
			if bom.Components != nil {
				Expect(lo.FromPtr(bom.Components)).To(Equal(expectedComponents))
			}
			// Verify metadata component injection
			if bom.Metadata != nil && bom.Metadata.Component != nil {
				props := lo.FromPtr(bom.Metadata.Component.Properties)
				if !config.AttackSurface.IsUndefined() {
					Expect(props).To(ContainElement(cdx.Property{Name: PropertyAttackSurface, Value: string(config.AttackSurface)}))
				}
				if !config.SecurityFunction.IsUndefined() {
					Expect(props).To(ContainElement(cdx.Property{Name: PropertySecurityFunction, Value: string(config.SecurityFunction)}))
				}
			}
		},
		Entry("should fail if BOM is nil",
			nil, Config{}, nil, MatchError("BOM is required")),
		Entry("should inject GOST properties if missing",
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
		Entry("should inject into metadata component",
			&cdx.BOM{
				Metadata: &cdx.Metadata{
					Component: &cdx.Component{Name: "image"},
				},
			},
			Config{AttackSurface: GostValueYes, SecurityFunction: GostValueNo},
			nil,
			Succeed()),
		Entry("should inject 'inherit' value",
			&cdx.BOM{
				Components: &[]cdx.Component{{Name: "test"}},
			},
			Config{AttackSurface: GostValueInherit, SecurityFunction: GostValueInherit},
			[]cdx.Component{
				{
					Name: "test",
					Properties: &[]cdx.Property{
						{Name: PropertyAttackSurface, Value: "inherit"},
						{Name: PropertySecurityFunction, Value: "inherit"},
					},
				},
			},
			Succeed()),
		Entry("should not overwrite existing GOST properties",
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
			Config{AttackSurface: GostValueYes, SecurityFunction: GostValueNo},
			[]cdx.Component{
				{
					Name: "test",
					Properties: &[]cdx.Property{
						{Name: PropertyAttackSurface, Value: "no"},
						{Name: PropertySecurityFunction, Value: "no"},
					},
				},
			},
			Succeed()),
	)
})
