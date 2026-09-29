package gost

import (
	"fmt"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/samber/lo"
)

// Validate checks that the BOM metadata component and every component, nested
// ones included, carry the mandatory GOST properties with valid values.
func Validate(bom *cdx.BOM) error {
	if bom == nil {
		return fmt.Errorf("BOM is required")
	}

	if bom.SpecVersion != cdx.SpecVersion1_6 {
		return fmt.Errorf("GOST validation requires CycloneDX version 1.6, got %s", bom.SpecVersion)
	}

	if bom.Metadata != nil && bom.Metadata.Component != nil {
		if err := ValidateComponent(bom.Metadata.Component); err != nil {
			return fmt.Errorf("metadata component %q: %w", bom.Metadata.Component.Name, err)
		}
		if err := validateComponents(lo.FromPtr(bom.Metadata.Component.Components)); err != nil {
			return err
		}
	}

	return validateComponents(lo.FromPtr(bom.Components))
}

func validateComponents(components []cdx.Component) error {
	for i := range components {
		if err := ValidateComponent(&components[i]); err != nil {
			return fmt.Errorf("component %q: %w", components[i].Name, err)
		}
		if err := validateComponents(lo.FromPtr(components[i].Components)); err != nil {
			return err
		}
	}

	return nil
}

// ValidateComponent checks if a single component has the mandatory GOST properties.
func ValidateComponent(comp *cdx.Component) error {
	a := newAccessor(comp)
	var missing []string

	if _, ok := a.GetAttackSurface(); !ok {
		missing = append(missing, PropertyAttackSurface)
	}
	if _, ok := a.GetSecurityFunction(); !ok {
		missing = append(missing, PropertySecurityFunction)
	}

	if err := ValidateComponentValues(comp); err != nil {
		return err
	}

	if len(missing) > 0 {
		return fmt.Errorf("missing mandatory GOST properties: %v", missing)
	}

	return nil
}

// ValidateValues checks that every GOST property present on the metadata
// component or on any component, nested ones included, carries a valid value.
// A component without the properties passes: the caller fills them in later.
func ValidateValues(bom *cdx.BOM) error {
	if bom == nil {
		return fmt.Errorf("BOM is required")
	}

	if bom.Metadata != nil && bom.Metadata.Component != nil {
		if err := ValidateComponentValues(bom.Metadata.Component); err != nil {
			return fmt.Errorf("metadata component %q: %w", bom.Metadata.Component.Name, err)
		}
		if err := validateComponentsValues(lo.FromPtr(bom.Metadata.Component.Components)); err != nil {
			return err
		}
	}

	return validateComponentsValues(lo.FromPtr(bom.Components))
}

func validateComponentsValues(components []cdx.Component) error {
	for i := range components {
		if err := ValidateComponentValues(&components[i]); err != nil {
			return fmt.Errorf("component %q: %w", components[i].Name, err)
		}
		if err := validateComponentsValues(lo.FromPtr(components[i].Components)); err != nil {
			return err
		}
	}

	return nil
}

// ValidateComponentValues checks the GOST properties a single component
// carries, ignoring the ones it lacks.
func ValidateComponentValues(comp *cdx.Component) error {
	a := newAccessor(comp)

	if as, ok := a.GetAttackSurface(); ok && !IsValidAttackSurfaceValue(as.String()) {
		return fmt.Errorf("invalid value for %s: %q (expected 'yes', 'no' or 'indirect')", PropertyAttackSurface, as)
	}

	if sf, ok := a.GetSecurityFunction(); ok && !IsValidSecurityFunctionValue(sf.String()) {
		return fmt.Errorf("invalid value for %s: %q (expected 'yes' or 'no')", PropertySecurityFunction, sf)
	}

	return nil
}
