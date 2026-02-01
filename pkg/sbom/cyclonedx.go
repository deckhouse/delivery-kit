package sbom

import (
	"bytes"
	"fmt"

	cdx "github.com/CycloneDX/cyclonedx-go"
)

const (
	// SyftLocationPathProperty is the property name for syft location path.
	SyftLocationPathProperty = "syft:location:0:path"
)

// ParseCycloneDXBOM parses a CycloneDX BOM from JSON bytes.
func ParseCycloneDXBOM(data []byte) (*cdx.BOM, error) {
	bom := new(cdx.BOM)
	decoder := cdx.NewBOMDecoder(bytes.NewReader(data), cdx.BOMFileFormatJSON)
	if err := decoder.Decode(bom); err != nil {
		return nil, fmt.Errorf("unable to parse CycloneDX BOM: %w", err)
	}
	return bom, nil
}

// ToJSON serializes CycloneDX BOM to JSON bytes.
func ToJSON(bom *cdx.BOM) ([]byte, error) {
	var buf bytes.Buffer
	encoder := cdx.NewBOMEncoder(&buf, cdx.BOMFileFormatJSON)
	encoder.SetPretty(true)
	if err := encoder.Encode(bom); err != nil {
		return nil, fmt.Errorf("unable to encode CycloneDX BOM: %w", err)
	}
	return buf.Bytes(), nil
}

// GetComponentsCount returns the number of components in a BOM.
func GetComponentsCount(bom *cdx.BOM) int {
	if bom == nil || bom.Components == nil {
		return 0
	}
	return len(*bom.Components)
}

// GetComponents returns the components slice from a BOM, or an empty slice if nil.
func GetComponents(bom *cdx.BOM) []cdx.Component {
	if bom == nil || bom.Components == nil {
		return nil
	}
	return *bom.Components
}

// SetComponents sets the components in a BOM.
func SetComponents(bom *cdx.BOM, components []cdx.Component) {
	if bom != nil {
		bom.Components = &components
	}
}

// CloneBOMMetadata creates a new BOM with the same metadata but empty components.
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

// MergeSBOMs merges multiple CycloneDX BOMs into a single BOM.
// Components from all BOMs are combined, duplicates are kept.
func MergeSBOMs(boms ...*cdx.BOM) *cdx.BOM {
	if len(boms) == 0 {
		return nil
	}

	// Find first non-nil BOM as base
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
