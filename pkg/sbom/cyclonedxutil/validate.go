package cyclonedxutil

import (
	"encoding/json"
	"fmt"
	"strings"
	"sync"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/xeipuuv/gojsonschema"
)

var (
	bom16Schema          *gojsonschema.Schema
	bom16SchemaOnce      sync.Once
	errCycloneDX16Schema error

	hashAlgorithms     map[string]struct{}
	hashAlgorithmsOnce sync.Once
	errHashAlgorithms  error

	spdxLicenseIDs     map[string]struct{}
	spdxLicenseIDsOnce sync.Once
	errSPDXLicenseIDs  error
)

// HashAlgorithmAllowed reports whether alg is a member of the "hash-alg" enum of
// the embedded CycloneDX 1.6 schema — the same schema ValidateCycloneDX16Schema
// checks against, so callers stay in sync with it without duplicating the list.
// It returns an error only if the embedded schema cannot be parsed.
func HashAlgorithmAllowed(alg string) (bool, error) {
	hashAlgorithmsOnce.Do(func() {
		hashAlgorithms, errHashAlgorithms = loadHashAlgorithms()
	})
	if errHashAlgorithms != nil {
		return false, errHashAlgorithms
	}

	_, ok := hashAlgorithms[alg]
	return ok, nil
}

func loadHashAlgorithms() (map[string]struct{}, error) {
	var schema struct {
		Definitions struct {
			HashAlg struct {
				Enum []string `json:"enum"`
			} `json:"hash-alg"`
		} `json:"definitions"`
	}
	if err := json.Unmarshal([]byte(bom_1_6_SchemaValue), &schema); err != nil {
		return nil, fmt.Errorf("parse embedded CycloneDX 1.6 schema: %w", err)
	}
	if len(schema.Definitions.HashAlg.Enum) == 0 {
		return nil, fmt.Errorf("embedded CycloneDX 1.6 schema has no hash-alg enum")
	}

	algs := make(map[string]struct{}, len(schema.Definitions.HashAlg.Enum))
	for _, alg := range schema.Definitions.HashAlg.Enum {
		algs[alg] = struct{}{}
	}
	return algs, nil
}

// SPDXLicenseIDKnown reports whether id is a member of the SPDX license list
// embedded with the CycloneDX 1.6 schema — the enum ValidateCycloneDX16Schema
// checks license.id against, so callers stay in sync with it. The match is
// case-sensitive like the schema's. It returns an error only if the embedded
// schema cannot be parsed.
func SPDXLicenseIDKnown(id string) (bool, error) {
	spdxLicenseIDsOnce.Do(func() {
		spdxLicenseIDs, errSPDXLicenseIDs = loadSPDXLicenseIDs()
	})
	if errSPDXLicenseIDs != nil {
		return false, errSPDXLicenseIDs
	}

	_, ok := spdxLicenseIDs[id]
	return ok, nil
}

func loadSPDXLicenseIDs() (map[string]struct{}, error) {
	var schema struct {
		Enum []string `json:"enum"`
	}
	if err := json.Unmarshal([]byte(spdx_SchemaValue), &schema); err != nil {
		return nil, fmt.Errorf("parse embedded SPDX schema: %w", err)
	}
	if len(schema.Enum) == 0 {
		return nil, fmt.Errorf("embedded SPDX schema has no enum")
	}

	ids := make(map[string]struct{}, len(schema.Enum))
	for _, id := range schema.Enum {
		ids[id] = struct{}{}
	}
	return ids, nil
}

// preloadCycloneDX16Schema ensures offline usage because of the network restrictions.
func preloadCycloneDX16Schema() (*gojsonschema.Schema, error) {
	sl := gojsonschema.NewSchemaLoader()

	// The CycloneDX 1.6 schema $refs the JSF and SPDX schemas; both are added to
	// the loader up front so it never fetches them over the network.
	for name, value := range map[string]string{"JSF": jsf_0_82_SchemaValue, "SPDX": spdx_SchemaValue} {
		if err := sl.AddSchemas(gojsonschema.NewStringLoader(value)); err != nil {
			return nil, fmt.Errorf("failed to add %s schema: %w", name, err)
		}
	}

	loader := gojsonschema.NewStringLoader(bom_1_6_SchemaValue)
	// We use sl.Compile directly. It will automatically detect the $id from the JSON content
	// and register it. sync.Once ensures we don't do this more than once per process.
	return sl.Compile(loader)
}

// ValidateCycloneDX16Schema validates the given JSON bytes against the CycloneDX 1.6 JSON Schema.
func ValidateCycloneDX16Schema(jsonBytes []byte) error {
	bom16SchemaOnce.Do(func() {
		bom16Schema, errCycloneDX16Schema = preloadCycloneDX16Schema()
	})

	if errCycloneDX16Schema != nil {
		return fmt.Errorf("failed to load CycloneDX 1.6 schema: %w", errCycloneDX16Schema)
	}

	documentLoader := gojsonschema.NewBytesLoader(jsonBytes)
	result, err := bom16Schema.Validate(documentLoader)
	if err != nil {
		return fmt.Errorf("failed to execute schema validation: %w", err)
	}

	if !result.Valid() {
		var errs []string
		for _, desc := range result.Errors() {
			errs = append(errs, desc.String())
		}
		return fmt.Errorf("cyclonedx: schema validation errors: %s", strings.Join(errs, "; "))
	}

	return nil
}

// ValidateBOM validates the given CycloneDX BOM against the CycloneDX 1.6 JSON Schema.
func ValidateBOM(bom *cdx.BOM) error {
	if bom == nil {
		return nil
	}

	jsonBytes, err := json.Marshal(bom)
	if err != nil {
		return fmt.Errorf("encode BOM for validation: %w", err)
	}

	return ValidateCycloneDX16Schema(jsonBytes)
}
