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
		result.SourceLangs = append(result.SourceLangs, gost.GetComponentSourceLangs(&components[i])...)

		nested := aggregateGOST(lo.FromPtr(components[i].Components))
		result.AttackSurface = gost.Max(result.AttackSurface, nested.AttackSurface)
		result.SecurityFunction = gost.Max(result.SecurityFunction, nested.SecurityFunction)
		result.SourceLangs = append(result.SourceLangs, nested.SourceLangs...)
	}
	result.SourceLangs = gost.UnionSourceLangs(result.SourceLangs)
	return result
}

// aggregateSourceLangs unions the source languages of the images — the ones on their
// components as well as the ones already present at the image BOM level (document
// properties, root component).
func aggregateSourceLangs(images []*ImageSBOM) []string {
	var langs []string
	for _, img := range images {
		langs = append(langs, gost.CollectBOMSourceLangs(img.BOM)...)
	}

	return gost.UnionSourceLangs(langs)
}

// applyGOSTToContainer fills the attack surface and security function of the container
// component when it does not declare its own, and unions the aggregated source languages
// with the ones it already carries.
func applyGOSTToContainer(comp *cdx.Component, values GOSTValues) {
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

	gost.SetComponentSourceLangs(comp, append(gost.GetComponentSourceLangs(comp), values.SourceLangs...))
}
