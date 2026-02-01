package sbom

import (
	"path/filepath"
	"strings"

	cdx "github.com/CycloneDX/cyclonedx-go"
)

// FilterComponentsByDestPath filters components from the source SBOM
// that match the source paths from COPY instruction.
// It updates the location path in filtered components to reflect the destination path.
func FilterComponentsByDestPath(sourceBOM *cdx.BOM, srcPaths []string, dstPath string) *cdx.BOM {
	if sourceBOM == nil {
		return nil
	}

	filteredBOM := CloneBOMMetadata(sourceBOM)
	filteredComponents := make([]cdx.Component, 0)

	for _, component := range GetComponents(sourceBOM) {
		locationPath := GetLocationPath(component)
		if locationPath == "" {
			continue
		}

		if matchesCopyPath(locationPath, srcPaths) {
			updatedComponent := CloneComponent(component)
			newPath := transformPath(locationPath, srcPaths, dstPath)
			SetLocationPath(&updatedComponent, newPath)
			filteredComponents = append(filteredComponents, updatedComponent)
		}
	}

	SetComponents(filteredBOM, filteredComponents)
	return filteredBOM
}

// matchesCopyPath checks if a component's location path matches any of the source paths.
func matchesCopyPath(locationPath string, srcPaths []string) bool {
	for _, srcPath := range srcPaths {
		if matchesSinglePath(locationPath, srcPath) {
			return true
		}
	}
	return false
}

// matchesSinglePath checks if locationPath matches a single source path pattern.
func matchesSinglePath(locationPath, srcPath string) bool {
	// Handle glob patterns
	if strings.Contains(srcPath, "*") {
		matched, _ := filepath.Match(srcPath, locationPath)
		return matched
	}

	// Exact match
	if locationPath == srcPath {
		return true
	}

	// Directory match (locationPath is under srcPath)
	return strings.HasPrefix(locationPath, ensureTrailingSlash(srcPath))
}

// transformPath transforms the source path to the destination path
// based on COPY instruction semantics.
func transformPath(locationPath string, srcPaths []string, dstPath string) string {
	for _, srcPath := range srcPaths {
		if transformed, ok := tryTransformPath(locationPath, srcPath, dstPath); ok {
			return transformed
		}
	}
	return locationPath
}

// tryTransformPath attempts to transform locationPath based on srcPath and dstPath.
// Returns the transformed path and true if successful, or empty string and false otherwise.
func tryTransformPath(locationPath, srcPath, dstPath string) (string, bool) {
	// Handle glob patterns
	if strings.Contains(srcPath, "*") {
		if matched, _ := filepath.Match(srcPath, locationPath); matched {
			return filepath.Join(dstPath, filepath.Base(locationPath)), true
		}
		return "", false
	}

	// Exact file match
	if locationPath == srcPath {
		if strings.HasSuffix(dstPath, "/") {
			return filepath.Join(dstPath, filepath.Base(srcPath)), true
		}
		return dstPath, true
	}

	// Directory match
	srcWithSlash := ensureTrailingSlash(srcPath)
	if strings.HasPrefix(locationPath, srcWithSlash) {
		relativePath := strings.TrimPrefix(locationPath, srcWithSlash)
		return filepath.Join(dstPath, relativePath), true
	}

	return "", false
}

// ensureTrailingSlash ensures the path ends with a trailing slash.
func ensureTrailingSlash(path string) string {
	if strings.HasSuffix(path, "/") {
		return path
	}
	return path + "/"
}
