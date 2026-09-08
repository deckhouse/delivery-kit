package ispras

import (
	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/samber/lo"
)

func NewImageSBOM(name string, bom *cdx.BOM) *ImageSBOM {
	return &ImageSBOM{
		Name: name,
		BOM:  bom,
		GOST: aggregateGOST(lo.FromPtr(bom.Components)),
	}
}
