package cyclonedxutil

import (
	"bytes"
	"fmt"

	cdx "github.com/CycloneDX/cyclonedx-go"
)

// ToJSON encodes the BOM to JSON using CycloneDX 1.6 specification.
func ToJSON(bom *cdx.BOM) ([]byte, error) {
	var buf bytes.Buffer
	if err := cdx.NewBOMEncoder(&buf, cdx.BOMFileFormatJSON).EncodeVersion(bom, cdx.SpecVersion1_6); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

// BuildCycloneDX16BOMFromJSON builds a CycloneDX 1.6 BOM from JSON bytes.
func BuildCycloneDX16BOMFromJSON(data []byte) (*cdx.BOM, error) {
	bom := &cdx.BOM{}
	if err := cdx.NewBOMDecoder(bytes.NewReader(data), cdx.BOMFileFormatJSON).Decode(bom); err != nil {
		return nil, fmt.Errorf("sbom: invalid CycloneDX JSON: %w", err)
	}

	if bom.SpecVersion != cdx.SpecVersion1_6 {
		return nil, fmt.Errorf("sbom: unsupported CycloneDX spec version %q (expected %q)", bom.SpecVersion, cdx.SpecVersion1_6)
	}

	return bom, nil
}
