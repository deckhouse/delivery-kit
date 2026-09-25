package ispras

import (
	cdx "github.com/CycloneDX/cyclonedx-go"
)

func NewImageSBOM(name string, bom *cdx.BOM) *ImageSBOM {
	return &ImageSBOM{
		Name: name,
		BOM:  bom,
	}
}
