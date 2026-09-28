package cyclonedxutil

import (
	"bytes"
	"fmt"
	"strings"

	cdx "github.com/CycloneDX/cyclonedx-go"
)

// ToJSON encodes the BOM to JSON using CycloneDX 1.6 specification.
func ToJSON(bom *cdx.BOM) ([]byte, error) {
	if err := validateEncodableHashes(bom); err != nil {
		return nil, err
	}

	var buf bytes.Buffer
	if err := cdx.NewBOMEncoder(&buf, cdx.BOMFileFormatJSON).EncodeVersion(bom, cdx.SpecVersion1_6); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

// validateEncodableHashes guards the digests that survive encoding. CycloneDX
// accepted GOST R 34.11-2012 only in 1.7, so the 1.6 encoder drops a STREEBOG
// hash from a component — silently, leaving the SBOM a digest short. The same
// encoder never touches the hashes of an external reference, which is why the
// digest of a source distribution comes through. A STREEBOG hash on a component
// is therefore a mistake worth a build failure rather than a missing field
// noticed at validation time.
func validateEncodableHashes(bom *cdx.BOM) error {
	if bom == nil {
		return nil
	}

	var roots []cdx.Component
	if bom.Metadata != nil && bom.Metadata.Component != nil {
		roots = append(roots, *bom.Metadata.Component)
	}
	if bom.Components != nil {
		roots = append(roots, *bom.Components...)
	}

	for len(roots) > 0 {
		comp := roots[0]
		roots = roots[1:]

		if comp.Components != nil {
			roots = append(roots, *comp.Components...)
		}
		if comp.Hashes == nil {
			continue
		}

		for _, hash := range *comp.Hashes {
			if !strings.HasPrefix(strings.ToUpper(string(hash.Algorithm)), "STREEBOG") {
				continue
			}
			return fmt.Errorf(
				"sbom: component %q carries a %s hash, which the CycloneDX %s encoder drops: a STREEBOG digest belongs on a source-distribution external reference",
				comp.Name, hash.Algorithm, cdx.SpecVersion1_6,
			)
		}
	}

	return nil
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
