package ispras

import (
	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/samber/lo"
)

func NewImageSBOM(name string, bom *cdx.BOM) *ImageSBOM {
	components := lo.FromPtr(bom.Components)
	if bom.Metadata != nil && bom.Metadata.Component != nil {
		components = append([]cdx.Component{*bom.Metadata.Component}, components...)
	}

	return &ImageSBOM{
		Name: name,
		BOM:  bom,
		GOST: aggregateGOST(components),
	}
}
