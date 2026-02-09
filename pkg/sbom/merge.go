package sbom

import (
	"encoding/json"
	"strings"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/google/uuid"

	"github.com/werf/common-go/pkg/util"
)

type MergeOpts struct {
	BaseBOM     *cdx.BOM
	ImportBOMs  []*cdx.BOM
	FragmentBOM *cdx.BOM
}

func (o MergeOpts) IsEmpty() bool {
	return o.BaseBOM == nil && len(o.ImportBOMs) == 0 && o.FragmentBOM == nil
}

func (o MergeOpts) Checksum() string {
	var parts []string
	for _, bom := range append([]*cdx.BOM{o.BaseBOM, o.FragmentBOM}, o.ImportBOMs...) {
		if cs := BOMChecksum(bom); cs != "" {
			parts = append(parts, cs)
		}
	}
	return strings.Join(parts, "-")
}

func MergeBOMs(target *cdx.BOM, opts MergeOpts) *cdx.BOM {
	result := &cdx.BOM{
		BOMFormat:    cdx.BOMFormat,
		SpecVersion:  cdx.SpecVersion1_6,
		Version:      1,
		SerialNumber: "urn:uuid:" + uuid.New().String(),
	}

	if target != nil && target.Metadata != nil {
		result.Metadata = target.Metadata
	}

	var components []cdx.Component
	components = appendBOMComponents(components, opts.BaseBOM)
	for _, bom := range opts.ImportBOMs {
		components = appendBOMComponents(components, bom)
	}
	components = appendBOMComponents(components, opts.FragmentBOM)
	components = appendBOMComponents(components, target)

	result.Components = &components
	return result
}

func appendBOMComponents(dest []cdx.Component, bom *cdx.BOM) []cdx.Component {
	if bom != nil && bom.Components != nil {
		return append(dest, *bom.Components...)
	}
	return dest
}

func BOMChecksum(bom *cdx.BOM) string {
	if bom == nil {
		return ""
	}
	data, err := json.Marshal(bom)
	if err != nil {
		return ""
	}

	return util.Sha256Hash(string(data))
}

func ToJSON(bom *cdx.BOM) ([]byte, error) {
	return json.Marshal(bom)
}
