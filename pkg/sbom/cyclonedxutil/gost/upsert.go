package gost

import (
	"fmt"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/samber/lo"
)

// Upsert inserts or updates mandatory GOST properties in the BOM metadata component
// and every component, nested ones included. An attack surface of `yes` describes
// the components an attacker reaches directly, so it lands on the roots of the
// dependency tree; everything pulled in by another component gets `indirect`.
// Every other value, and the security function in all cases, applies unchanged.
func Upsert(bom *cdx.BOM, config Config) error {
	if bom == nil {
		return fmt.Errorf("BOM is required")
	}

	dependent := config
	if config.AttackSurface == GostValueYes {
		dependent.AttackSurface = GostValueIndirect
	}

	targets := dependencyTargets(bom)

	if bom.Metadata != nil && bom.Metadata.Component != nil {
		SetComponent(bom.Metadata.Component, config)
		setComponents(lo.FromPtr(bom.Metadata.Component.Components), config, dependent, targets)
	}

	setComponents(lo.FromPtr(bom.Components), config, dependent, targets)

	return nil
}

func setComponents(components []cdx.Component, root, dependent Config, targets map[string]struct{}) {
	for i := range components {
		comp := &components[i]

		cfg := root
		if _, ok := targets[comp.BOMRef]; ok {
			cfg = dependent
		}

		SetComponent(comp, cfg)
		setComponents(lo.FromPtr(comp.Components), root, dependent, targets)
	}
}

// dependencyTargets collects every bom-ref another component depends on. A
// component missing from the set is a root of the dependency tree: nothing else
// in the image pulls it in. An empty `dependencies` section therefore makes
// every component a root, which is what the catalogers that report no tree at
// all produce.
//
// Edges sourced at the image itself are skipped: a cataloger that lists every
// package under the image root describes what the image contains, not what one
// package pulls in, and honoring those edges would leave the tree without a
// single root.
func dependencyTargets(bom *cdx.BOM) map[string]struct{} {
	var rootRef string
	if bom.Metadata != nil && bom.Metadata.Component != nil {
		rootRef = bom.Metadata.Component.BOMRef
	}

	targets := make(map[string]struct{})
	for _, dep := range lo.FromPtr(bom.Dependencies) {
		if rootRef != "" && dep.Ref == rootRef {
			continue
		}

		for _, ref := range lo.FromPtr(dep.Dependencies) {
			if ref != dep.Ref {
				targets[ref] = struct{}{}
			}
		}
	}

	return targets
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
