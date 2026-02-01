package sbom

import (
	"testing"

	"github.com/stretchr/testify/assert"
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
	assert.NoError(t, err)
	assert.NotNil(t, bom)
	assert.Equal(t, "CycloneDX", bom.BomFormat)
	assert.Equal(t, "1.6", bom.SpecVersion)
	assert.Len(t, bom.Components, 2)
	assert.Equal(t, "curl", bom.Components[0].Name)
	assert.Equal(t, "/bin/curl", bom.Components[0].GetLocationPath())
}

func TestGetLocationPath(t *testing.T) {
	component := CycloneDXComponent{
		Name:    "test",
		Version: "1.0",
		Properties: []CycloneDXProperty{
			{Name: "syft:package:type", Value: "binary"},
			{Name: "syft:location:0:path", Value: "/usr/bin/test"},
		},
	}

	assert.Equal(t, "/usr/bin/test", component.GetLocationPath())

	componentNoPath := CycloneDXComponent{
		Name:    "test",
		Version: "1.0",
		Properties: []CycloneDXProperty{
			{Name: "syft:package:type", Value: "binary"},
		},
	}

	assert.Equal(t, "", componentNoPath.GetLocationPath())
}

func TestFilterComponentsByDestPath(t *testing.T) {
	sourceBOM := &CycloneDXBOM{
		BomFormat:   "CycloneDX",
		SpecVersion: "1.6",
		Components: []CycloneDXComponent{
			{
				Name:    "curl",
				Version: "8.12.1",
				Properties: []CycloneDXProperty{
					{Name: "syft:location:0:path", Value: "/usr/bin/curl"},
				},
			},
			{
				Name:    "bash",
				Version: "5.0",
				Properties: []CycloneDXProperty{
					{Name: "syft:location:0:path", Value: "/usr/bin/bash"},
				},
			},
			{
				Name:    "libcurl",
				Version: "8.12.1",
				Properties: []CycloneDXProperty{
					{Name: "syft:location:0:path", Value: "/usr/lib/libcurl.so"},
				},
			},
		},
	}

	// Test filtering single file
	filteredBOM := FilterComponentsByDestPath(sourceBOM, []string{"/usr/bin/curl"}, "/bin/curl")
	assert.NotNil(t, filteredBOM)
	assert.Len(t, filteredBOM.Components, 1)
	assert.Equal(t, "curl", filteredBOM.Components[0].Name)
	assert.Equal(t, "/bin/curl", filteredBOM.Components[0].GetLocationPath())

	// Test filtering directory
	filteredBOM = FilterComponentsByDestPath(sourceBOM, []string{"/usr/bin/"}, "/app/bin/")
	assert.NotNil(t, filteredBOM)
	assert.Len(t, filteredBOM.Components, 2) // curl and bash
}

func TestMatchesCopyPath(t *testing.T) {
	tests := []struct {
		name         string
		locationPath string
		srcPaths     []string
		dstPath      string
		expected     bool
	}{
		{
			name:         "exact match",
			locationPath: "/usr/bin/curl",
			srcPaths:     []string{"/usr/bin/curl"},
			dstPath:      "/bin/curl",
			expected:     true,
		},
		{
			name:         "no match",
			locationPath: "/usr/bin/curl",
			srcPaths:     []string{"/usr/bin/bash"},
			dstPath:      "/bin/bash",
			expected:     false,
		},
		{
			name:         "directory match",
			locationPath: "/usr/bin/curl",
			srcPaths:     []string{"/usr/bin/"},
			dstPath:      "/bin/",
			expected:     true,
		},
		{
			name:         "glob match",
			locationPath: "/usr/bin/curl",
			srcPaths:     []string{"/usr/bin/*"},
			dstPath:      "/bin/",
			expected:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := matchesCopyPath(tt.locationPath, tt.srcPaths, tt.dstPath)
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

func TestMergeSBOMs(t *testing.T) {
	bom1 := &CycloneDXBOM{
		BomFormat:   "CycloneDX",
		SpecVersion: "1.6",
		Components: []CycloneDXComponent{
			{Name: "curl", Version: "8.12.1"},
		},
	}

	bom2 := &CycloneDXBOM{
		BomFormat:   "CycloneDX",
		SpecVersion: "1.6",
		Components: []CycloneDXComponent{
			{Name: "bash", Version: "5.0"},
		},
	}

	merged := MergeSBOMs(bom1, bom2)
	assert.NotNil(t, merged)
	assert.Len(t, merged.Components, 2)

	// Test with nil
	merged = MergeSBOMs(nil, bom1)
	assert.NotNil(t, merged)
	assert.Len(t, merged.Components, 1)

	// Test all nil
	merged = MergeSBOMs(nil, nil)
	assert.Nil(t, merged)
}
