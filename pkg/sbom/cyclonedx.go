package sbom

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
)

// CycloneDXBOM represents a CycloneDX BOM document.
type CycloneDXBOM struct {
	Schema       string               `json:"$schema,omitempty"`
	BomFormat    string               `json:"bomFormat"`
	SpecVersion  string               `json:"specVersion"`
	SerialNumber string               `json:"serialNumber,omitempty"`
	Version      int                  `json:"version"`
	Metadata     *CycloneDXMetadata   `json:"metadata,omitempty"`
	Components   []CycloneDXComponent `json:"components,omitempty"`
}

// CycloneDXMetadata represents metadata section of CycloneDX BOM.
type CycloneDXMetadata struct {
	Timestamp string              `json:"timestamp,omitempty"`
	Tools     *CycloneDXTools     `json:"tools,omitempty"`
	Component *CycloneDXComponent `json:"component,omitempty"`
}

// CycloneDXTools represents tools section of CycloneDX BOM metadata.
type CycloneDXTools struct {
	Components []CycloneDXComponent `json:"components,omitempty"`
}

// CycloneDXComponent represents a component in CycloneDX BOM.
type CycloneDXComponent struct {
	BomRef     string              `json:"bom-ref,omitempty"`
	Type       string              `json:"type,omitempty"`
	Author     string              `json:"author,omitempty"`
	Name       string              `json:"name,omitempty"`
	Version    string              `json:"version,omitempty"`
	CPE        string              `json:"cpe,omitempty"`
	PURL       string              `json:"purl,omitempty"`
	Properties []CycloneDXProperty `json:"properties,omitempty"`
}

// CycloneDXProperty represents a property in CycloneDX component.
type CycloneDXProperty struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

const (
	// SyftLocationPathProperty is the property name for syft location path.
	SyftLocationPathProperty = "syft:location:0:path"
)

// ParseCycloneDXBOM parses a CycloneDX BOM from JSON bytes.
func ParseCycloneDXBOM(data []byte) (*CycloneDXBOM, error) {
	var bom CycloneDXBOM
	if err := json.Unmarshal(data, &bom); err != nil {
		return nil, fmt.Errorf("unable to parse CycloneDX BOM: %w", err)
	}
	return &bom, nil
}

// ToJSON serializes CycloneDX BOM to JSON bytes.
func (bom *CycloneDXBOM) ToJSON() ([]byte, error) {
	return json.MarshalIndent(bom, "", "  ")
}

// GetLocationPath returns the location path from component properties.
// It looks for the "syft:location:0:path" property.
func (c *CycloneDXComponent) GetLocationPath() string {
	for _, prop := range c.Properties {
		if prop.Name == SyftLocationPathProperty {
			return prop.Value
		}
	}
	return ""
}

// CopyFromSBOMEntry represents SBOM data for a COPY --from instruction.
type CopyFromSBOMEntry struct {
	// SourceImageRef is the reference to the source image (COPY --from=<image>).
	SourceImageRef string
	// SourcePaths are the source paths from the COPY instruction.
	SourcePaths []string
	// DestPath is the destination path from the COPY instruction.
	DestPath string
	// FilteredBOM is the SBOM filtered by the destination path.
	FilteredBOM *CycloneDXBOM
}

// FilterComponentsByDestPath filters components from the source SBOM
// that match the destination path from COPY instruction.
// It matches components where the syft:location:0:path property starts with
// or equals the dstPath (considering path transformations).
func FilterComponentsByDestPath(sourceBOM *CycloneDXBOM, srcPaths []string, dstPath string) *CycloneDXBOM {
	if sourceBOM == nil {
		return nil
	}

	filteredBOM := &CycloneDXBOM{
		Schema:       sourceBOM.Schema,
		BomFormat:    sourceBOM.BomFormat,
		SpecVersion:  sourceBOM.SpecVersion,
		SerialNumber: sourceBOM.SerialNumber,
		Version:      sourceBOM.Version,
		Metadata:     sourceBOM.Metadata,
		Components:   make([]CycloneDXComponent, 0),
	}

	for _, component := range sourceBOM.Components {
		locationPath := component.GetLocationPath()
		if locationPath == "" {
			continue
		}

		// Check if the component's location path matches any of the copied paths
		if matchesCopyPath(locationPath, srcPaths, dstPath) {
			// Create a copy of the component with updated path
			updatedComponent := component
			updatedComponent.Properties = updateLocationPath(component.Properties, srcPaths, dstPath)
			filteredBOM.Components = append(filteredBOM.Components, updatedComponent)
		}
	}

	return filteredBOM
}

// matchesCopyPath checks if a component's location path matches the COPY instruction paths.
// srcPaths are the source paths from COPY instruction (e.g., ["/usr/bin/curl"])
// dstPath is the destination path from COPY instruction (e.g., "/bin/curl")
// locationPath is the component's path in the source image (e.g., "/usr/bin/curl")
func matchesCopyPath(locationPath string, srcPaths []string, dstPath string) bool {
	for _, srcPath := range srcPaths {
		// Handle glob patterns in srcPath
		if strings.Contains(srcPath, "*") {
			matched, _ := filepath.Match(srcPath, locationPath)
			if matched {
				return true
			}
			continue
		}

		// Exact match
		if locationPath == srcPath {
			return true
		}

		// Check if locationPath is under srcPath (for directory copies)
		if strings.HasPrefix(locationPath, ensureTrailingSlash(srcPath)) {
			return true
		}
	}
	return false
}

// updateLocationPath updates the syft:location:0:path property to reflect the new path
// after COPY instruction (from source path to destination path).
func updateLocationPath(properties []CycloneDXProperty, srcPaths []string, dstPath string) []CycloneDXProperty {
	result := make([]CycloneDXProperty, len(properties))
	copy(result, properties)

	for i, prop := range result {
		if prop.Name == SyftLocationPathProperty {
			newPath := transformPath(prop.Value, srcPaths, dstPath)
			result[i].Value = newPath
			break
		}
	}

	return result
}

// transformPath transforms the source path to the destination path
// based on COPY instruction semantics.
func transformPath(locationPath string, srcPaths []string, dstPath string) string {
	for _, srcPath := range srcPaths {
		if strings.Contains(srcPath, "*") {
			// For glob patterns, keep the filename and put it in dstPath
			matched, _ := filepath.Match(srcPath, locationPath)
			if matched {
				return filepath.Join(dstPath, filepath.Base(locationPath))
			}
			continue
		}

		if locationPath == srcPath {
			// If copying a single file to a specific destination
			if strings.HasSuffix(dstPath, "/") {
				// dstPath is a directory
				return filepath.Join(dstPath, filepath.Base(srcPath))
			}
			// dstPath is the target filename
			return dstPath
		}

		// For directory copies, replace the srcPath prefix with dstPath
		srcWithSlash := ensureTrailingSlash(srcPath)
		if strings.HasPrefix(locationPath, srcWithSlash) {
			relativePath := strings.TrimPrefix(locationPath, srcWithSlash)
			return filepath.Join(dstPath, relativePath)
		}
	}

	return locationPath
}

func ensureTrailingSlash(path string) string {
	if strings.HasSuffix(path, "/") {
		return path
	}
	return path + "/"
}

// MergeSBOMs merges multiple CycloneDX BOMs into a single BOM.
// Components from all BOMs are combined, duplicates are kept.
func MergeSBOMs(boms ...*CycloneDXBOM) *CycloneDXBOM {
	if len(boms) == 0 {
		return nil
	}

	// Use the first non-nil BOM as the base
	var baseBOM *CycloneDXBOM
	for _, bom := range boms {
		if bom != nil {
			baseBOM = bom
			break
		}
	}

	if baseBOM == nil {
		return nil
	}

	merged := &CycloneDXBOM{
		Schema:       baseBOM.Schema,
		BomFormat:    baseBOM.BomFormat,
		SpecVersion:  baseBOM.SpecVersion,
		SerialNumber: baseBOM.SerialNumber,
		Version:      baseBOM.Version,
		Metadata:     baseBOM.Metadata,
		Components:   make([]CycloneDXComponent, 0),
	}

	for _, bom := range boms {
		if bom != nil {
			merged.Components = append(merged.Components, bom.Components...)
		}
	}

	return merged
}
