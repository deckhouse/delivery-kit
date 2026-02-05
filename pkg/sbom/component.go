package sbom

import (
	cdx "github.com/CycloneDX/cyclonedx-go"
)

func GetProperty(component cdx.Component, name string) string {
	if component.Properties == nil {
		return ""
	}

	for _, prop := range *component.Properties {
		if prop.Name == name {
			return prop.Value
		}
	}

	return ""
}

func GetLocationPaths(component cdx.Component) []string {
	if component.Properties == nil {
		return nil
	}

	var paths []string
	for _, prop := range *component.Properties {
		if IsLocationPathProperty(prop.Name) {
			paths = append(paths, prop.Value)
		}
	}

	return paths
}

func GetLocationPath(component cdx.Component) string {
	if component.Properties == nil {
		return ""
	}

	for _, prop := range *component.Properties {
		if IsLocationPathProperty(prop.Name) {
			return prop.Value
		}
	}

	return ""
}
