package sbom

import (
	"bytes"
	"fmt"

	cdx "github.com/CycloneDX/cyclonedx-go"
)

const (
	SyftLocationPathProperty = "syft:location:0:path"
)

func ParseCycloneDXBOM(data []byte) (*cdx.BOM, error) {
	bom := new(cdx.BOM)
	decoder := cdx.NewBOMDecoder(bytes.NewReader(data), cdx.BOMFileFormatJSON)
	if err := decoder.Decode(bom); err != nil {
		return nil, fmt.Errorf("unable to parse CycloneDX BOM: %w", err)
	}
	return bom, nil
}

func ToJSON(bom *cdx.BOM) ([]byte, error) {
	var buf bytes.Buffer
	encoder := cdx.NewBOMEncoder(&buf, cdx.BOMFileFormatJSON)
	encoder.SetPretty(true)
	if err := encoder.Encode(bom); err != nil {
		return nil, fmt.Errorf("unable to encode CycloneDX BOM: %w", err)
	}
	return buf.Bytes(), nil
}

func GetComponentsCount(bom *cdx.BOM) int {
	if bom == nil || bom.Components == nil {
		return 0
	}
	return len(*bom.Components)
}

func GetComponents(bom *cdx.BOM) []cdx.Component {
	if bom == nil || bom.Components == nil {
		return nil
	}
	return *bom.Components
}

func SetComponents(bom *cdx.BOM, components []cdx.Component) {
	if bom != nil {
		bom.Components = &components
	}
}

func CloneBOMMetadata(source *cdx.BOM) *cdx.BOM {
	if source == nil {
		return nil
	}
	return &cdx.BOM{
		BOMFormat:    source.BOMFormat,
		SpecVersion:  source.SpecVersion,
		SerialNumber: source.SerialNumber,
		Version:      source.Version,
		Metadata:     source.Metadata,
		Components:   &[]cdx.Component{},
	}
}

func MergeSBOMs(boms ...*cdx.BOM) *cdx.BOM {
	if len(boms) == 0 {
		return nil
	}

	var baseBOM *cdx.BOM
	for _, bom := range boms {
		if bom != nil {
			baseBOM = bom
			break
		}
	}

	if baseBOM == nil {
		return nil
	}

	merged := CloneBOMMetadata(baseBOM)
	mergedComponents := make([]cdx.Component, 0)

	for _, bom := range boms {
		mergedComponents = append(mergedComponents, GetComponents(bom)...)
	}

	SetComponents(merged, mergedComponents)
	return merged
}
