package ispras

import (
	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/samber/lo"

	"github.com/werf/werf/v3/pkg/sbom/cyclonedxutil/gost"
)

func aggregateGOST(components []cdx.Component) GOSTValues {
	var result GOSTValues
	for i := range components {
		cfg := gost.GetComponent(&components[i])
		result.AttackSurface = gost.Max(result.AttackSurface, cfg.AttackSurface)
		result.SecurityFunction = gost.Max(result.SecurityFunction, cfg.SecurityFunction)

		nested := aggregateGOST(lo.FromPtr(components[i].Components))
		result.AttackSurface = gost.Max(result.AttackSurface, nested.AttackSurface)
		result.SecurityFunction = gost.Max(result.SecurityFunction, nested.SecurityFunction)
	}
	return result
}

func setMissingGOSTOnComponent(comp *cdx.Component, values GOSTValues) {
	current := gost.GetComponent(comp)

	attack := current.AttackSurface
	if attack == gost.GostValueUndefined {
		attack = values.AttackSurface
	}

	security := current.SecurityFunction
	if security == gost.GostValueUndefined {
		security = values.SecurityFunction
	}

	gost.SetComponent(comp, gost.Config{
		AttackSurface:    attack,
		SecurityFunction: security,
	})
}
