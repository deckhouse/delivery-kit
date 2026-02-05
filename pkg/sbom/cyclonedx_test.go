package sbom

import (
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseCycloneDXBOM(t *testing.T) {
	sbomJSON := `{
		"$schema": "http://cyclonedx.org/schema/bom-1.6.schema.json",
		"bomFormat": "CycloneDX",
		"specVersion": "1.6",
		"serialNumber": "urn:uuid:test",
		"version": 1,
		"components": [
			{
				"bom-ref": "pkg:generic/curl@8.12.1",
				"type": "application",
				"name": "curl",
				"version": "8.12.1",
				"properties": [
					{
						"name": "syft:location:0:path",
						"value": "/bin/curl"
					}
				]
			},
			{
				"bom-ref": "pkg:generic/bash@5.0",
				"type": "application",
				"name": "bash",
				"version": "5.0",
				"properties": [
					{
						"name": "syft:location:0:path",
						"value": "/usr/bin/bash"
					}
				]
			}
		]
	}`

	bom, err := ParseCycloneDXBOM([]byte(sbomJSON))
	require.NoError(t, err)
	require.NotNil(t, bom)
	assert.Equal(t, "CycloneDX", bom.BOMFormat)
	assert.Equal(t, cdx.SpecVersion1_6, bom.SpecVersion)
	assert.Equal(t, 2, GetComponentsCount(bom))

	components := GetComponents(bom)
	assert.Equal(t, "curl", components[0].Name)
	assert.Equal(t, "/bin/curl", GetLocationPath(components[0]))
}

func TestGetLocationPath(t *testing.T) {
	t.Run("returns first location path", func(t *testing.T) {
		component := cdx.Component{
			Name:    "test",
			Version: "1.0",
			Properties: &[]cdx.Property{
				{Name: "syft:package:type", Value: "binary"},
				{Name: "syft:location:0:path", Value: "/usr/bin/test"},
			},
		}
		assert.Equal(t, "/usr/bin/test", GetLocationPath(component))
	})

	t.Run("returns first of multiple paths", func(t *testing.T) {
		component := cdx.Component{
			Name:    "test",
			Version: "1.0",
			Properties: &[]cdx.Property{
				{Name: "syft:location:0:path", Value: "/usr/bin/test"},
				{Name: "syft:location:1:path", Value: "/usr/local/bin/test"},
			},
		}
		assert.Equal(t, "/usr/bin/test", GetLocationPath(component))
	})

	t.Run("returns empty for no path", func(t *testing.T) {
		componentNoPath := cdx.Component{
			Name:    "test",
			Version: "1.0",
			Properties: &[]cdx.Property{
				{Name: "syft:package:type", Value: "binary"},
			},
		}
		assert.Equal(t, "", GetLocationPath(componentNoPath))
	})

	t.Run("returns empty for nil properties", func(t *testing.T) {
		componentNilProps := cdx.Component{
			Name:    "test",
			Version: "1.0",
		}
		assert.Equal(t, "", GetLocationPath(componentNilProps))
	})
}

func TestIsLocationPathProperty(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected bool
	}{
		{"index 0", "syft:location:0:path", true},
		{"index 1", "syft:location:1:path", true},
		{"index 42", "syft:location:42:path", true},
		{"index 999", "syft:location:999:path", true},
		{"wrong prefix", "other:location:0:path", false},
		{"wrong suffix", "syft:location:0:other", false},
		{"missing index", "syft:location::path", false},
		{"non-numeric index", "syft:location:abc:path", false},
		{"package type", "syft:package:type", false},
		{"empty", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, IsLocationPathProperty(tt.input))
		})
	}
}

func TestGetLocationPaths(t *testing.T) {
	t.Run("returns all location paths", func(t *testing.T) {
		component := cdx.Component{
			Name: "test",
			Properties: &[]cdx.Property{
				{Name: "syft:location:0:path", Value: "/usr/bin/test"},
				{Name: "syft:package:type", Value: "binary"},
				{Name: "syft:location:1:path", Value: "/usr/local/bin/test"},
				{Name: "syft:location:5:path", Value: "/opt/test"},
			},
		}
		paths := GetLocationPaths(component)
		assert.Len(t, paths, 3)
		assert.Contains(t, paths, "/usr/bin/test")
		assert.Contains(t, paths, "/usr/local/bin/test")
		assert.Contains(t, paths, "/opt/test")
	})

	t.Run("returns nil for no paths", func(t *testing.T) {
		component := cdx.Component{
			Name: "test",
			Properties: &[]cdx.Property{
				{Name: "syft:package:type", Value: "binary"},
			},
		}
		assert.Nil(t, GetLocationPaths(component))
	})

	t.Run("returns nil for nil properties", func(t *testing.T) {
		component := cdx.Component{Name: "test"}
		assert.Nil(t, GetLocationPaths(component))
	})
}

func TestToJSON(t *testing.T) {
	bom := &cdx.BOM{
		BOMFormat:   "CycloneDX",
		SpecVersion: cdx.SpecVersion1_6,
		Version:     1,
		Components: &[]cdx.Component{
			{
				Type:    cdx.ComponentTypeApplication,
				Name:    "test",
				Version: "1.0",
			},
		},
	}

	data, err := ToJSON(bom)
	require.NoError(t, err)
	assert.NotEmpty(t, data)
	assert.Contains(t, string(data), "test")
	assert.Contains(t, string(data), "1.0")

	parsedBOM, err := ParseCycloneDXBOM(data)
	require.NoError(t, err)
	assert.Equal(t, 1, GetComponentsCount(parsedBOM))
	assert.Equal(t, "test", GetComponents(parsedBOM)[0].Name)
}

func TestGetComponentsCount(t *testing.T) {
	tests := []struct {
		name     string
		bom      *cdx.BOM
		expected int
	}{
		{"nil BOM", nil, 0},
		{"nil components", &cdx.BOM{BOMFormat: "CycloneDX"}, 0},
		{"empty components", &cdx.BOM{Components: &[]cdx.Component{}}, 0},
		{"with components", &cdx.BOM{Components: &[]cdx.Component{{Name: "a"}, {Name: "b"}}}, 2},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, GetComponentsCount(tt.bom))
		})
	}
}

func TestGetComponents(t *testing.T) {
	t.Run("nil BOM returns nil", func(t *testing.T) {
		assert.Nil(t, GetComponents(nil))
	})

	t.Run("nil components returns nil", func(t *testing.T) {
		bom := &cdx.BOM{BOMFormat: "CycloneDX"}
		assert.Nil(t, GetComponents(bom))
	})

	t.Run("returns components", func(t *testing.T) {
		components := []cdx.Component{{Name: "test"}}
		bom := &cdx.BOM{Components: &components}
		assert.Equal(t, components, GetComponents(bom))
	})
}
