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

func matchesCopyPath(locationPath string, srcPaths []string) bool {
	for _, srcPath := range srcPaths {
		if matchesSinglePath(locationPath, srcPath) {
			return true
		}
	}
	return false
}

func matchesSinglePath(locationPath, srcPath string) bool {
	if strings.Contains(srcPath, "*") {
		matched, _ := filepath.Match(srcPath, locationPath)
		return matched
	}

	if locationPath == srcPath {
		return true
	}

	return strings.HasPrefix(locationPath, ensureTrailingSlash(srcPath))
}

func transformPath(locationPath string, srcPaths []string, dstPath string) string {
	for _, srcPath := range srcPaths {
		if transformed, ok := tryTransformPath(locationPath, srcPath, dstPath); ok {
			return transformed
		}
	}
	return locationPath
}

func tryTransformPath(locationPath, srcPath, dstPath string) (string, bool) {
	if strings.Contains(srcPath, "*") {
		if matched, _ := filepath.Match(srcPath, locationPath); matched {
			return filepath.Join(dstPath, filepath.Base(locationPath)), true
		}
		return "", false
	}

	if locationPath == srcPath {
		if strings.HasSuffix(dstPath, "/") {
			return filepath.Join(dstPath, filepath.Base(srcPath)), true
		}
		return dstPath, true
	}

	srcWithSlash := ensureTrailingSlash(srcPath)
	if strings.HasPrefix(locationPath, srcWithSlash) {
		relativePath := strings.TrimPrefix(locationPath, srcWithSlash)
		return filepath.Join(dstPath, relativePath), true
	}

	return "", false
}

func ensureTrailingSlash(path string) string {
	if strings.HasSuffix(path, "/") {
		return path
	}
	return path + "/"
}
