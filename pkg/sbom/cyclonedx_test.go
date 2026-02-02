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
	component := cdx.Component{
		Name:    "test",
		Version: "1.0",
		Properties: &[]cdx.Property{
			{Name: "syft:package:type", Value: "binary"},
			{Name: "syft:location:0:path", Value: "/usr/bin/test"},
		},
	}

	assert.Equal(t, "/usr/bin/test", GetLocationPath(component))

	componentNoPath := cdx.Component{
		Name:    "test",
		Version: "1.0",
		Properties: &[]cdx.Property{
			{Name: "syft:package:type", Value: "binary"},
		},
	}

	assert.Equal(t, "", GetLocationPath(componentNoPath))

	componentNilProps := cdx.Component{
		Name:    "test",
		Version: "1.0",
	}
	assert.Equal(t, "", GetLocationPath(componentNilProps))
}

func TestSetLocationPath(t *testing.T) {
	component := cdx.Component{
		Name:    "test",
		Version: "1.0",
		Properties: &[]cdx.Property{
			{Name: "syft:location:0:path", Value: "/old/path"},
		},
	}
	SetLocationPath(&component, "/new/path")
	assert.Equal(t, "/new/path", GetLocationPath(component))

	componentNoPath := cdx.Component{
		Name:    "test",
		Version: "1.0",
		Properties: &[]cdx.Property{
			{Name: "syft:package:type", Value: "binary"},
		},
	}
	SetLocationPath(&componentNoPath, "/added/path")
	assert.Equal(t, "/added/path", GetLocationPath(componentNoPath))

	componentNilProps := cdx.Component{
		Name:    "test",
		Version: "1.0",
	}
	SetLocationPath(&componentNilProps, "/nil/path")
	assert.Equal(t, "/nil/path", GetLocationPath(componentNilProps))
}

func TestFilterComponentsByDestPath(t *testing.T) {
	sourceBOM := &cdx.BOM{
		BOMFormat:   "CycloneDX",
		SpecVersion: cdx.SpecVersion1_6,
		Components: &[]cdx.Component{
			{
				Name:    "curl",
				Version: "8.12.1",
				Properties: &[]cdx.Property{
					{Name: "syft:location:0:path", Value: "/usr/bin/curl"},
				},
			},
			{
				Name:    "bash",
				Version: "5.0",
				Properties: &[]cdx.Property{
					{Name: "syft:location:0:path", Value: "/usr/bin/bash"},
				},
			},
			{
				Name:    "libcurl",
				Version: "8.12.1",
				Properties: &[]cdx.Property{
					{Name: "syft:location:0:path", Value: "/usr/lib/libcurl.so"},
				},
			},
		},
	}

	filteredBOM := FilterComponentsByDestPath(sourceBOM, []string{"/usr/bin/curl"}, "/bin/curl")
	assert.NotNil(t, filteredBOM)
	assert.NotNil(t, filteredBOM.Components)
	assert.Len(t, *filteredBOM.Components, 1)
	assert.Equal(t, "curl", (*filteredBOM.Components)[0].Name)
	assert.Equal(t, "/bin/curl", GetLocationPath((*filteredBOM.Components)[0]))

	filteredBOM = FilterComponentsByDestPath(sourceBOM, []string{"/usr/bin/"}, "/app/bin/")
	assert.NotNil(t, filteredBOM)
	assert.Len(t, *filteredBOM.Components, 2)
}

func TestMatchesCopyPath(t *testing.T) {
	tests := []struct {
		name         string
		locationPath string
		srcPaths     []string
		expected     bool
	}{
		{
			name:         "exact match",
			locationPath: "/usr/bin/curl",
			srcPaths:     []string{"/usr/bin/curl"},
			expected:     true,
		},
		{
			name:         "no match",
			locationPath: "/usr/bin/curl",
			srcPaths:     []string{"/usr/bin/bash"},
			expected:     false,
		},
		{
			name:         "directory match",
			locationPath: "/usr/bin/curl",
			srcPaths:     []string{"/usr/bin/"},
			expected:     true,
		},
		{
			name:         "glob match",
			locationPath: "/usr/bin/curl",
			srcPaths:     []string{"/usr/bin/*"},
			expected:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := matchesCopyPath(tt.locationPath, tt.srcPaths)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestTransformPath(t *testing.T) {
	tests := []struct {
		name         string
		locationPath string
		srcPaths     []string
		dstPath      string
		expected     string
	}{
		{
			name:         "single file to file",
			locationPath: "/usr/bin/curl",
			srcPaths:     []string{"/usr/bin/curl"},
			dstPath:      "/bin/curl",
			expected:     "/bin/curl",
		},
		{
			name:         "single file to directory",
			locationPath: "/usr/bin/curl",
			srcPaths:     []string{"/usr/bin/curl"},
			dstPath:      "/bin/",
			expected:     "/bin/curl",
		},
		{
			name:         "directory to directory",
			locationPath: "/usr/bin/curl",
			srcPaths:     []string{"/usr/bin/"},
			dstPath:      "/app/bin/",
			expected:     "/app/bin/curl",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := transformPath(tt.locationPath, tt.srcPaths, tt.dstPath)
			assert.Equal(t, tt.expected, result)
		})
	}
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

func TestSetComponents(t *testing.T) {
	bom := &cdx.BOM{}
	components := []cdx.Component{{Name: "test"}}

	SetComponents(bom, components)

	assert.Equal(t, 1, GetComponentsCount(bom))
	assert.Equal(t, "test", GetComponents(bom)[0].Name)
}

func TestCloneBOMMetadata(t *testing.T) {
	t.Run("nil returns nil", func(t *testing.T) {
		assert.Nil(t, CloneBOMMetadata(nil))
	})

	t.Run("clones metadata with empty components", func(t *testing.T) {
		source := &cdx.BOM{
			BOMFormat:    "CycloneDX",
			SpecVersion:  cdx.SpecVersion1_6,
			SerialNumber: "urn:uuid:test",
			Version:      1,
			Components:   &[]cdx.Component{{Name: "original"}},
		}

		cloned := CloneBOMMetadata(source)

		require.NotNil(t, cloned)
		assert.Equal(t, source.BOMFormat, cloned.BOMFormat)
		assert.Equal(t, source.SpecVersion, cloned.SpecVersion)
		assert.Equal(t, source.SerialNumber, cloned.SerialNumber)
		assert.Equal(t, 0, GetComponentsCount(cloned))
	})
}
