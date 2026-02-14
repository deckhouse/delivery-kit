package cyclonedxutil

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/google/uuid"
	jsonpatch "gopkg.in/evanphx/json-patch.v5"
	syaml "sigs.k8s.io/yaml"
)

// BuildCycloneDX16BOMFromYAMLFragment builds a CycloneDX BOM from a YAML document that can be:
//   - a full CycloneDX BOM document, or
//   - a partial "fragment" (e.g. only `components:`, `metadata:`, etc).
//
// Process:
//   - convert YAML -> JSON (strict) as-is
//   - create an empty BOM document based on the requested standard and encode it as JSON
//   - merge fragment JSON into the base JSON using JSON Merge Patch (RFC 7396)
//   - decode merged JSON into the resulting BOM document
func BuildCycloneDX16BOMFromYAMLFragment(fragmentYAML []byte) (*cdx.BOM, error) {
	if len(bytes.TrimSpace(fragmentYAML)) == 0 {
		return nil, fmt.Errorf("sbom: document fragment is empty")
	}

	jsonFromYAML, err := syaml.YAMLToJSONStrict(fragmentYAML)
	if err != nil {
		return nil, fmt.Errorf("sbom: invalid YAML fragment: %w", err)
	}

	// Create a base (empty) BOM for the requested standard.
	baseBOM := newCycloneDX16BOM()

	baseJSON, err := json.Marshal(baseBOM)
	if err != nil {
		return nil, fmt.Errorf("sbom: failed to build base CycloneDX document: %w", err)
	}

	// Merge fragment into base using JSON Merge Patch.
	mergedJSON, err := jsonpatch.MergePatch(baseJSON, jsonFromYAML)
	if err != nil {
		return nil, fmt.Errorf("sbom: failed to merge YAML fragment into base document: %w", err)
	}

	return BuildCycloneDX16BOMFromJSON(mergedJSON)
}

// BuildCycloneDX16BOMFromJSON builds a CycloneDX BOM document from JSON bytes and validates it.
// Currently, only CycloneDX@1.6 is supported.
func BuildCycloneDX16BOMFromJSON(bomJSON []byte) (*cdx.BOM, error) {
	if len(bytes.TrimSpace(bomJSON)) == 0 {
		return nil, fmt.Errorf("cyclonedxutil: document json is empty")
	}

	var bom cdx.BOM
	if err := json.Unmarshal(bomJSON, &bom); err != nil {
		return nil, fmt.Errorf("cyclonedxutil: failed to decode CycloneDX document: %w", err)
	}

	// Final sanity checks on the decoded structure.
	if err := validateCycloneDX16BOM(&bom); err != nil {
		return nil, err
	}

	// As a "hard-ish" check, ensure cyclonedx-go can encode the resulting BOM as JSON 1.6.
	if _, err := ToJSON(&bom); err != nil {
		return nil, fmt.Errorf("sbom: invalid CycloneDX document for specVersion=1.6: %w", err)
	}

	return &bom, nil
}

func validateCycloneDX16BOM(b *cdx.BOM) error {
	if b == nil {
		return fmt.Errorf("cyclonedxutil: internal error: nil bom")
	}

	// Required fields for CycloneDX JSON.
	if b.BOMFormat != cdx.BOMFormat {
		return fmt.Errorf("cyclonedxutil: cyclonedx: invalid bomFormat %q (expected %q)", b.BOMFormat, cdx.BOMFormat)
	}
	if b.SpecVersion != cdx.SpecVersion1_6 {
		return fmt.Errorf("cyclonedxutil: cyclonedx: invalid specVersion %q (expected %q)", b.SpecVersion.String(), cdx.SpecVersion1_6.String())
	}
	if b.Version < 1 {
		return fmt.Errorf("cyclonedxutil: cyclonedx: version must be >= 1")
	}

	// serialNumber is optional in spec, but we always populate it; keep it valid.
	if b.SerialNumber != "" {
		if !strings.HasPrefix(b.SerialNumber, "urn:uuid:") {
			return fmt.Errorf("cyclonedxutil: cyclonedx: serialNumber must have prefix %q", "urn:uuid:")
		}
		if _, err := uuid.Parse(strings.TrimPrefix(b.SerialNumber, "urn:uuid:")); err != nil {
			return fmt.Errorf("cyclonedxutil: cyclonedx: serialNumber must be a valid urn uuid: %w", err)
		}
	}

	return nil
}

// NewEmptyBOM creates an empty but valid CycloneDX 1.6 BOM.
// This is useful for base images like "scratch" that have no components.
func NewEmptyBOM() *cdx.BOM {
	b := newCycloneDX16BOM()
	b.Components = &[]cdx.Component{}
	return b
}

func newCycloneDX16BOM() *cdx.BOM {
	return &cdx.BOM{
		BOMFormat:    cdx.BOMFormat,
		SpecVersion:  cdx.SpecVersion1_6,
		Version:      1,
		SerialNumber: "urn:uuid:" + uuid.New().String(),
	}
}
