package gost

import (
	"fmt"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/samber/lo"
)

// Upsert inserts or updates mandatory GOST properties in the BOM metadata component
// and every component, nested ones included.
func Upsert(bom *cdx.BOM, config Config) error {
	if bom == nil {
		return fmt.Errorf("BOM is required")
	}

	if bom.Metadata != nil && bom.Metadata.Component != nil {
		SetComponent(bom.Metadata.Component, config)
		setComponents(lo.FromPtr(bom.Metadata.Component.Components), config)
	}

	setComponents(lo.FromPtr(bom.Components), config)

	return nil
}

func setComponents(components []cdx.Component, config Config) {
	for i := range components {
		SetComponent(&components[i], config)
		setComponents(lo.FromPtr(components[i].Components), config)
	}
}

// SetComponent inserts or updates mandatory GOST properties in a single component.
func SetComponent(comp *cdx.Component, config Config) {
	a := newAccessor(comp)
	a.SetAttackSurface(config.AttackSurface)
	a.SetSecurityFunction(config.SecurityFunction)
}

func GetComponent(comp *cdx.Component) Config {
	a := newAccessor(comp)
	attack, _ := a.GetAttackSurface()
	security, _ := a.GetSecurityFunction()
	return Config{
		AttackSurface:    attack,
		SecurityFunction: security,
	}
}
