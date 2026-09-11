package ispras

import (
	cdx "github.com/CycloneDX/cyclonedx-go"

	"github.com/werf/werf/v3/pkg/sbom/cyclonedxutil/gost"
)

func componentWithLangs(name, langs string) cdx.Component {
	comp := cdx.Component{
		Type:       cdx.ComponentTypeLibrary,
		BOMRef:     name,
		Name:       name,
		Properties: &[]cdx.Property{{Name: gost.PropertyAttackSurface, Value: gost.GostValueYes.String()}},
	}
	if langs != "" {
		*comp.Properties = append(*comp.Properties, cdx.Property{Name: gost.PropertySourceLangs, Value: langs})
	}

	return comp
}

func imageSBOM(name string, components ...cdx.Component) *ImageSBOM {
	return NewImageSBOM(name, &cdx.BOM{
		BOMFormat:   "CycloneDX",
		SpecVersion: cdx.SpecVersion1_6,
		Components:  &components,
	})
}
