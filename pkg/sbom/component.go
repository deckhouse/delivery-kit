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

	*component.Properties = append(props, cdx.Property{
		Name:  name,
		Value: value,
	})
}

func GetLocationPath(component cdx.Component) string {
	return GetProperty(component, SyftLocationPathProperty)
}

func SetLocationPath(component *cdx.Component, path string) {
	SetProperty(component, SyftLocationPathProperty, path)
}

func CloneComponent(component cdx.Component) cdx.Component {
	copied := component
	if component.Properties != nil {
		props := make([]cdx.Property, len(*component.Properties))
		copy(props, *component.Properties)
		copied.Properties = &props
	}
	return copied
}
