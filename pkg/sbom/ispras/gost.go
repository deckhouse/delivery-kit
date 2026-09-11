package ispras

import (
	"sort"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/samber/lo"

	"github.com/werf/werf/v2/pkg/sbom/cyclonedxutil/gost"
)

var gostPrecedence = map[gost.GostValue]int{
	gost.GostValueUndefined: 0,
	gost.GostValueNo:        1,
	gost.GostValueIndirect:  2,
	gost.GostValueYes:       3,
}

func aggregateGOST(components []cdx.Component) GOSTValues {
	var result GOSTValues
	for i := range components {
		cfg := gost.GetComponent(&components[i])
		result.AttackSurface = maxGOSTValue(result.AttackSurface, cfg.AttackSurface)
		result.SecurityFunction = maxGOSTValue(result.SecurityFunction, cfg.SecurityFunction)
	}
	result.SourceLangs = gost.CollectSourceLangs(components)
	return result
}

// aggregateSourceLangs unions the source languages of the images. The result is sorted:
// images are assembled in a non-deterministic order, and the product SBOM has to stay
// comparable across runs.
func aggregateSourceLangs(images []*ImageSBOM) []string {
	var langs []string
	for _, img := range images {
		langs = append(langs, img.GOST.SourceLangs...)
	}
	langs = lo.Uniq(langs)
	sort.Strings(langs)

	return langs
}

func maxGOSTValue(a, b gost.GostValue) gost.GostValue {
	if gostPrecedence[b] > gostPrecedence[a] {
		return b
	}
	return a
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

	gost.SetComponentSourceLangs(comp, append(gost.GetComponentSourceLangs(comp), values.SourceLangs...))
}
