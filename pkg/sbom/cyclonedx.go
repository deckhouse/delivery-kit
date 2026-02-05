package sbom

import (
	"bytes"
	"fmt"
	"regexp"

	cdx "github.com/CycloneDX/cyclonedx-go"
)

var syftLocationPathRegex = regexp.MustCompile(`^syft:location:\d+:path$`)

func IsLocationPathProperty(name string) bool {
	return syftLocationPathRegex.MatchString(name)
}

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
