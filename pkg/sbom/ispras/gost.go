package ispras

import (
	"context"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/samber/lo"

	"github.com/werf/werf/v3/pkg/sbom/cyclonedxutil/gost"
)

func aggregateGOST(ctx context.Context, components []cdx.Component) GOSTValues {
	var result GOSTValues
	for i := range components {
		cfg := gost.GetComponent(&components[i])
		result.AttackSurface = gost.Max(result.AttackSurface, cfg.AttackSurface)
		result.SecurityFunction = gost.Max(result.SecurityFunction, cfg.SecurityFunction)
		result.SourceLangs = append(result.SourceLangs, gost.GetComponentSourceLangs(ctx, &components[i])...)

		nested := aggregateGOST(ctx, lo.FromPtr(components[i].Components))
		result.AttackSurface = gost.Max(result.AttackSurface, nested.AttackSurface)
		result.SecurityFunction = gost.Max(result.SecurityFunction, nested.SecurityFunction)
		result.SourceLangs = append(result.SourceLangs, nested.SourceLangs...)
	}
	result.SourceLangs = gost.UnionSourceLangs(ctx, result.SourceLangs)
	return result
}

// aggregateSourceLangs unions the source languages of the images — the ones on their
// components as well as the ones already present at the image BOM level (document
// properties, root component).
func aggregateSourceLangs(ctx context.Context, images []*ImageSBOM) []string {
	var langs []string
	for _, img := range images {
		langs = append(langs, gost.CollectBOMSourceLangs(ctx, img.BOM)...)
	}

	return gost.UnionSourceLangs(ctx, langs)
}

// applyGOSTToContainer fills the attack surface and security function of the container
// component when it does not declare its own, and unions the aggregated source languages
// with the ones it already carries.
func applyGOSTToContainer(ctx context.Context, comp *cdx.Component, values GOSTValues) {
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

	gost.SetComponentSourceLangs(ctx, comp, append(gost.GetComponentSourceLangs(ctx, comp), values.SourceLangs...))
}
