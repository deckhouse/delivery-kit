package nativegate

import (
	"context"
	"fmt"
	"path"

	cdx "github.com/CycloneDX/cyclonedx-go"
)

func ImageOriginals(ctx context.Context, bom *cdx.BOM, platform string) ([]Original, error) {
	if err := ValidateImageSource(ctx, "/", "source", bom, platform); err != nil {
		return nil, err
	}
	components := map[string]cdx.Component{}
	for _, component := range *bom.Components {
		components[component.BOMRef] = component
	}
	dependencies := map[string][]string{}
	if bom.Dependencies != nil {
		for _, dep := range *bom.Dependencies {
			if dep.Dependencies != nil {
				dependencies[dep.Ref] = *dep.Dependencies
			}
		}
	}
	var result []Original
	for _, file := range *bom.Components {
		if file.Type != cdx.ComponentTypeFile {
			continue
		}
		if !path.IsAbs(file.Name) || path.Clean(file.Name) != file.Name || file.Hashes == nil {
			return nil, fmt.Errorf("%s: no-data: invalid SBOM file", file.Name)
		}
		checksum := ""
		for _, hash := range *file.Hashes {
			if hash.Algorithm == cdx.HashAlgoSHA256 {
				checksum = "sha256:" + hash.Value
			}
		}
		if !digestPattern.MatchString(checksum) {
			return nil, fmt.Errorf("%s: no-data: missing SHA256 in source SBOM", file.Name)
		}
		ownerPURL, originalPath := "", ""
		if file.Properties != nil {
			for _, prop := range *file.Properties {
				if prop.Name == "dk:owner" {
					ownerPURL = prop.Value
				}
				if prop.Name == "dk:original-path" {
					originalPath = prop.Value
				}
			}
		}
		var owners []cdx.Component
		for _, ref := range dependencies[file.BOMRef] {
			component, exists := components[ref]
			if !exists {
				return nil, fmt.Errorf("%s: no-data: missing component %s", file.Name, ref)
			}
			if component.Type != cdx.ComponentTypeFile && (ownerPURL == "" || component.PackageURL == ownerPURL) {
				owners = append(owners, component)
			}
		}
		if len(owners) == 0 {
			return nil, fmt.Errorf("%s: no-data: no source component in SBOM", file.Name)
		}
		if ownerPURL != "" && len(owners) != 1 {
			return nil, fmt.Errorf("%s: ambiguous source component in SBOM", file.Name)
		}
		owner := owners[0]
		if ownerPURL == "" && len(owners) > 1 {
			if bom.Metadata.Component == nil {
				return nil, fmt.Errorf("%s: no-data: source image identity missing", file.Name)
			}
			owner = *bom.Metadata.Component
		}
		result = append(result, Original{Path: file.Name, SourcePath: originalPath, SHA256: checksum, Component: owner, Kind: "image"})
	}
	return result, nil
}
