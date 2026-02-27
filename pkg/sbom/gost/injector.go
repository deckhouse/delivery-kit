package gost

import (
	"fmt"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/samber/lo"
)

// Inject adds mandatory GOST properties to the BOM and all its components
// if they are not already present.
func Inject(bom *cdx.BOM, config Config) error {
	if bom == nil {
		return fmt.Errorf("BOM is required")
	}

	if bom.Metadata != nil && bom.Metadata.Component != nil {
		InjectIntoComponent(bom.Metadata.Component, config)
	}

	// NOTE: We only modify top-level components per the requirement.
	if bom.Components != nil {
		for i := range *bom.Components {
			InjectIntoComponent(&(*bom.Components)[i], config)
		}
	}

	return nil
}

// InjectIntoComponent adds mandatory GOST properties to a single component
// if they are not already present.
func InjectIntoComponent(comp *cdx.Component, config Config) {
	var hasAttackSurface, hasSecurityFunction bool

	for _, prop := range lo.FromPtr(comp.Properties) {
		if prop.Name == PropertyAttackSurface {
			hasAttackSurface = true
		}
		if prop.Name == PropertySecurityFunction {
			hasSecurityFunction = true
		}
	}

	if !hasAttackSurface && !config.AttackSurface.IsUndefined() {
		if comp.Properties == nil {
			comp.Properties = lo.ToPtr([]cdx.Property{})
		}
		*comp.Properties = append(*comp.Properties, cdx.Property{
			Name:  PropertyAttackSurface,
			Value: string(config.AttackSurface),
		})
	}
	if !hasSecurityFunction && !config.SecurityFunction.IsUndefined() {
		if comp.Properties == nil {
			comp.Properties = lo.ToPtr([]cdx.Property{})
		}
		*comp.Properties = append(*comp.Properties, cdx.Property{
			Name:  PropertySecurityFunction,
			Value: string(config.SecurityFunction),
		})
	}
}
