package sbom

import (
	cdx "github.com/CycloneDX/cyclonedx-go"
)

// GetProperty returns the value of a property by name from a component.
// Returns empty string if property is not found.
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

// SetProperty sets or updates a property value in a component.
func SetProperty(component *cdx.Component, name, value string) {
	if component.Properties == nil {
		component.Properties = &[]cdx.Property{}
	}

	props := *component.Properties
	for i, prop := range props {
		if prop.Name == name {
			props[i].Value = value
			return
		}
	}

	// Property not found, add it
	*component.Properties = append(props, cdx.Property{
		Name:  name,
		Value: value,
	})
}

// GetLocationPath returns the location path from component properties.
// It looks for the "syft:location:0:path" property.
func GetLocationPath(component cdx.Component) string {
	return GetProperty(component, SyftLocationPathProperty)
}

// SetLocationPath sets the location path in component properties.
func SetLocationPath(component *cdx.Component, path string) {
	SetProperty(component, SyftLocationPathProperty, path)
}

// CloneComponent creates a deep copy of a component.
// Only Properties are deep-copied, other pointer fields are shallow-copied.
func CloneComponent(component cdx.Component) cdx.Component {
	copied := component
	if component.Properties != nil {
		props := make([]cdx.Property, len(*component.Properties))
		copy(props, *component.Properties)
		copied.Properties = &props
	}
	return copied
}
