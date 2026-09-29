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
//
// The prefix match is deliberately case-insensitive, unlike the exact,
// case-sensitive match the enricher applies to a source-distribution reference:
// here the point is to catch a dropped digest whatever its casing, while there
// the point is the exact spelling the schema and the ISPRAS checker accept.
func validateEncodableHashes(bom *cdx.BOM) error {
	if bom == nil {
		return nil
	}

	// The component-bearing places werf's SBOM populates: the metadata
	// component, the top-level component tree (with each component's pedigree),
	// and the tools recorded as components. Legacy tools (metadata.tools.tools)
	// carry hashes too and are checked below since they are not cdx.Component
	// values. CycloneDX can also serialize component hashes under
	// bom.Formulation and vulnerability tools; werf emits neither, so the walk
	// does not descend into them.
	var roots []cdx.Component
	if bom.Metadata != nil {
		if bom.Metadata.Component != nil {
			roots = append(roots, *bom.Metadata.Component)
		}
		if tools := bom.Metadata.Tools; tools != nil {
			if tools.Components != nil {
				roots = append(roots, *tools.Components...)
			}
			if tools.Tools != nil {
				for _, tool := range *tools.Tools {
					if err := checkComponentHashes(tool.Name, tool.Hashes); err != nil {
						return err
					}
				}
			}
		}
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
		// A pedigree records the same package under other identities, each a
		// component whose hashes the encoder drops just the same.
		if p := comp.Pedigree; p != nil {
			if p.Ancestors != nil {
				roots = append(roots, *p.Ancestors...)
			}
			if p.Descendants != nil {
				roots = append(roots, *p.Descendants...)
			}
			if p.Variants != nil {
				roots = append(roots, *p.Variants...)
			}
		}

		if err := checkComponentHashes(comp.Name, comp.Hashes); err != nil {
			return err
		}
	}

	return nil
}

// checkComponentHashes fails when a component-like element carries a STREEBOG
// digest the 1.6 encoder would silently drop.
func checkComponentHashes(name string, hashes *[]cdx.Hash) error {
	if hashes == nil {
		return nil
	}

	for _, hash := range *hashes {
		if !strings.HasPrefix(strings.ToUpper(string(hash.Algorithm)), "STREEBOG") {
			continue
		}
		return fmt.Errorf(
			"sbom: component %q carries a %s hash, which the CycloneDX %s encoder drops: a STREEBOG digest belongs on a source-distribution external reference",
			name, hash.Algorithm, cdx.SpecVersion1_6,
		)
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
