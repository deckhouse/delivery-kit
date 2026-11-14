package nativegate

import (
	"context"
	"fmt"
	"slices"

	cdx "github.com/CycloneDX/cyclonedx-go"

	"github.com/werf/werf/v3/pkg/container_backend"
	"github.com/werf/werf/v3/pkg/sbom/shippedscope"
)

const emptyServiceFileProperty = "dk:empty-service-file"

func serviceFileName(name string) bool {
	return name == container_backend.SSHContainerAuthSockPath || name == container_backend.SSHHostAuthSockPath || name == container_backend.ServiceScriptPath
}

func excludeServiceFiles(index *shippedscope.FileIndex, owned []string) (map[string]shippedscope.File, error) {
	result := map[string]shippedscope.File{}
	for _, name := range owned {
		if !serviceFileName(name) {
			return nil, fmt.Errorf("%s: unknown service file path", name)
		}
		file, exists := index.Files[name]
		if exists && file.Size == 0 && file.Digest == digest(nil) {
			result[name] = file
			delete(index.Files, name)
		}
	}
	return result, nil
}

// ServiceFilesFromBOM reads mount evidence from a previously validated source BOM; destinations still require empty regular files.
func ServiceFilesFromBOM(ctx context.Context, bom *cdx.BOM) ([]string, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	var result []string
	if bom.Metadata == nil || bom.Metadata.Properties == nil {
		return result, nil
	}
	for _, property := range *bom.Metadata.Properties {
		if property.Name != emptyServiceFileProperty {
			continue
		}
		if !serviceFileName(property.Value) {
			return nil, fmt.Errorf("%s: unknown service file in source SBOM", property.Value)
		}
		result = append(result, property.Value)
	}
	slices.Sort(result)
	return slices.Compact(result), nil
}
