package sbom

import (
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func createTestBOM() *cdx.BOM {
	return &cdx.BOM{
		BOMFormat:   "CycloneDX",
		SpecVersion: cdx.SpecVersion1_6,
		Components: &[]cdx.Component{
			{
				Name:    "curl",
				Version: "8.5.0",
				Properties: &[]cdx.Property{
					{Name: SyftLocationPathProperty, Value: "/usr/bin/curl"},
				},
			},
			{
				Name:    "wget",
				Version: "1.21",
				Properties: &[]cdx.Property{
					{Name: SyftLocationPathProperty, Value: "/usr/bin/wget"},
				},
			},
			{
				Name:    "libcurl",
				Version: "8.5.0",
				Properties: &[]cdx.Property{
					{Name: SyftLocationPathProperty, Value: "/usr/lib/libcurl.so.4"},
				},
			},
			{
				Name:    "libssl",
				Version: "3.0.0",
				Properties: &[]cdx.Property{
					{Name: SyftLocationPathProperty, Value: "/usr/lib/ssl/libssl.so"},
				},
			},
			{
				Name:    "ca-certificates",
				Version: "2024.01",
				Properties: &[]cdx.Property{
					{Name: SyftLocationPathProperty, Value: "/etc/ssl/certs/ca-certificates.crt"},
				},
			},
			{
				Name:    "no-location",
				Version: "1.0",
			},
		},
	}
}

func TestFilterComponentsByDestPath_NilBOM(t *testing.T) {
	result := FilterComponentsByDestPath(nil, []string{"/usr/bin/"}, "/bin/")
	assert.Nil(t, result)
}

func TestFilterComponentsByDestPath_ExactFileMatch(t *testing.T) {
	bom := createTestBOM()

	result := FilterComponentsByDestPath(bom, []string{"/usr/bin/curl"}, "/app/curl")

	require.NotNil(t, result)
	assert.Equal(t, 1, GetComponentsCount(result))

	components := GetComponents(result)
	assert.Equal(t, "curl", components[0].Name)
	assert.Equal(t, "/app/curl", GetLocationPath(components[0]))
}

func TestFilterComponentsByDestPath_ExactFileToDirectory(t *testing.T) {
	bom := createTestBOM()

	result := FilterComponentsByDestPath(bom, []string{"/usr/bin/curl"}, "/app/")

	require.NotNil(t, result)
	assert.Equal(t, 1, GetComponentsCount(result))

	components := GetComponents(result)
	assert.Equal(t, "curl", components[0].Name)
	assert.Equal(t, "/app/curl", GetLocationPath(components[0]))
}

func TestFilterComponentsByDestPath_DirectoryMatch(t *testing.T) {
	bom := createTestBOM()

	result := FilterComponentsByDestPath(bom, []string{"/usr/bin/"}, "/copied/bin/")

	require.NotNil(t, result)
	assert.Equal(t, 2, GetComponentsCount(result))

	components := GetComponents(result)
	names := []string{components[0].Name, components[1].Name}
	assert.Contains(t, names, "curl")
	assert.Contains(t, names, "wget")

	for _, c := range components {
		path := GetLocationPath(c)
		if c.Name == "curl" {
			assert.Equal(t, "/copied/bin/curl", path)
		} else if c.Name == "wget" {
			assert.Equal(t, "/copied/bin/wget", path)
		}
	}
}

func TestFilterComponentsByDestPath_NestedDirectoryMatch(t *testing.T) {
	bom := createTestBOM()

	result := FilterComponentsByDestPath(bom, []string{"/usr/lib/"}, "/copied/lib/")

	require.NotNil(t, result)
	assert.Equal(t, 2, GetComponentsCount(result))

	components := GetComponents(result)
	for _, c := range components {
		path := GetLocationPath(c)
		if c.Name == "libcurl" {
			assert.Equal(t, "/copied/lib/libcurl.so.4", path)
		} else if c.Name == "libssl" {
			assert.Equal(t, "/copied/lib/ssl/libssl.so", path)
		}
	}
}

func TestFilterComponentsByDestPath_GlobPattern(t *testing.T) {
	bom := createTestBOM()

	result := FilterComponentsByDestPath(bom, []string{"/usr/bin/*"}, "/app/")

	require.NotNil(t, result)
	assert.Equal(t, 2, GetComponentsCount(result))

	components := GetComponents(result)
	for _, c := range components {
		path := GetLocationPath(c)
		assert.True(t, path == "/app/curl" || path == "/app/wget",
			"unexpected path: %s", path)
	}
}

func TestFilterComponentsByDestPath_MultipleSrcPaths(t *testing.T) {
	bom := createTestBOM()

	result := FilterComponentsByDestPath(bom, []string{"/usr/bin/curl", "/usr/bin/wget"}, "/tools/")

	require.NotNil(t, result)
	assert.Equal(t, 2, GetComponentsCount(result))
}

func TestFilterComponentsByDestPath_NoMatch(t *testing.T) {
	bom := createTestBOM()

	result := FilterComponentsByDestPath(bom, []string{"/opt/nonexistent"}, "/app/")

	require.NotNil(t, result)
	assert.Equal(t, 0, GetComponentsCount(result))
}

func TestFilterComponentsByDestPath_SkipsComponentsWithoutLocation(t *testing.T) {
	bom := createTestBOM()

	result := FilterComponentsByDestPath(bom, []string{"/"}, "/")

	require.NotNil(t, result)
	assert.Equal(t, 5, GetComponentsCount(result))
}

func TestFilterComponentsByDestPath_OriginalBOMNotModified(t *testing.T) {
	bom := createTestBOM()
	originalPath := GetLocationPath(GetComponents(bom)[0])

	_ = FilterComponentsByDestPath(bom, []string{"/usr/bin/curl"}, "/modified/curl")

	assert.Equal(t, originalPath, GetLocationPath(GetComponents(bom)[0]))
}

func TestFilterComponentsByDestPath_EtcSslDirectory(t *testing.T) {
	bom := createTestBOM()

	result := FilterComponentsByDestPath(bom, []string{"/etc/ssl/"}, "/copied/ssl/")

	require.NotNil(t, result)
	assert.Equal(t, 1, GetComponentsCount(result))

	components := GetComponents(result)
	assert.Equal(t, "ca-certificates", components[0].Name)
	assert.Equal(t, "/copied/ssl/certs/ca-certificates.crt", GetLocationPath(components[0]))
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
			srcPaths:     []string{"/usr/bin/wget"},
			expected:     false,
		},
		{
			name:         "directory match with trailing slash",
			locationPath: "/usr/bin/curl",
			srcPaths:     []string{"/usr/bin/"},
			expected:     true,
		},
		{
			name:         "directory match without trailing slash",
			locationPath: "/usr/bin/curl",
			srcPaths:     []string{"/usr/bin"},
			expected:     true,
		},
		{
			name:         "nested directory match",
			locationPath: "/usr/lib/ssl/libssl.so",
			srcPaths:     []string{"/usr/lib/"},
			expected:     true,
		},
		{
			name:         "glob pattern match",
			locationPath: "/usr/bin/curl",
			srcPaths:     []string{"/usr/bin/*"},
			expected:     true,
		},
		{
			name:         "glob pattern no match - nested",
			locationPath: "/usr/bin/subdir/tool",
			srcPaths:     []string{"/usr/bin/*"},
			expected:     false,
		},
		{
			name:         "multiple paths - first matches",
			locationPath: "/usr/bin/curl",
			srcPaths:     []string{"/usr/bin/curl", "/opt/curl"},
			expected:     true,
		},
		{
			name:         "multiple paths - second matches",
			locationPath: "/opt/curl",
			srcPaths:     []string{"/usr/bin/curl", "/opt/curl"},
			expected:     true,
		},
		{
			name:         "multiple paths - none match",
			locationPath: "/var/lib/data",
			srcPaths:     []string{"/usr/bin/", "/opt/"},
			expected:     false,
		},
		{
			name:         "partial path should not match",
			locationPath: "/usr/bin/curl",
			srcPaths:     []string{"/usr/bi"},
			expected:     false,
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
			name:         "exact file to file",
			locationPath: "/usr/bin/curl",
			srcPaths:     []string{"/usr/bin/curl"},
			dstPath:      "/bin/curl",
			expected:     "/bin/curl",
		},
		{
			name:         "exact file to directory",
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
		{
			name:         "nested path in directory",
			locationPath: "/usr/lib/ssl/certs/ca.crt",
			srcPaths:     []string{"/usr/lib/"},
			dstPath:      "/copied/",
			expected:     "/copied/ssl/certs/ca.crt",
		},
		{
			name:         "glob pattern",
			locationPath: "/usr/bin/curl",
			srcPaths:     []string{"/usr/bin/*"},
			dstPath:      "/app/",
			expected:     "/app/curl",
		},
		{
			name:         "no match returns original",
			locationPath: "/opt/tool",
			srcPaths:     []string{"/usr/bin/"},
			dstPath:      "/app/",
			expected:     "/opt/tool",
		},
		{
			name:         "first matching path wins",
			locationPath: "/usr/bin/curl",
			srcPaths:     []string{"/usr/bin/curl", "/usr/bin/"},
			dstPath:      "/app/mycurl",
			expected:     "/app/mycurl",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := transformPath(tt.locationPath, tt.srcPaths, tt.dstPath)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestCloneComponent(t *testing.T) {
	original := cdx.Component{
		Name:    "test",
		Version: "1.0",
		Properties: &[]cdx.Property{
			{Name: "key1", Value: "value1"},
			{Name: SyftLocationPathProperty, Value: "/original/path"},
		},
	}

	cloned := CloneComponent(original)

	assert.Equal(t, original.Name, cloned.Name)
	assert.Equal(t, original.Version, cloned.Version)
	assert.Equal(t, GetLocationPath(original), GetLocationPath(cloned))

	SetLocationPath(&cloned, "/modified/path")
	assert.Equal(t, "/original/path", GetLocationPath(original))
	assert.Equal(t, "/modified/path", GetLocationPath(cloned))
}

func TestCloneComponent_NilProperties(t *testing.T) {
	original := cdx.Component{
		Name:    "test",
		Version: "1.0",
	}

	cloned := CloneComponent(original)

	assert.Equal(t, original.Name, cloned.Name)
	assert.Nil(t, cloned.Properties)
}

func TestEnsureTrailingSlash(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"/path", "/path/"},
		{"/path/", "/path/"},
		{"/", "/"},
		{"", "/"},
		{"/usr/bin", "/usr/bin/"},
		{"/usr/bin/", "/usr/bin/"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := ensureTrailingSlash(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestFilterComponentsByDestPath_DockerfileCopyFrom(t *testing.T) {
	alpineBOM := &cdx.BOM{
		BOMFormat:   "CycloneDX",
		SpecVersion: cdx.SpecVersion1_6,
		Components: &[]cdx.Component{
			{
				Name:    "curl",
				Version: "8.5.0-r0",
				Type:    cdx.ComponentTypeApplication,
				Properties: &[]cdx.Property{
					{Name: SyftLocationPathProperty, Value: "/usr/bin/curl"},
					{Name: "syft:package:type", Value: "apk"},
				},
			},
			{
				Name:    "libcurl",
				Version: "8.5.0-r0",
				Properties: &[]cdx.Property{
					{Name: SyftLocationPathProperty, Value: "/usr/lib/libcurl.so.4"},
				},
			},
			{
				Name:    "busybox",
				Version: "1.36.1-r15",
				Properties: &[]cdx.Property{
					{Name: SyftLocationPathProperty, Value: "/bin/busybox"},
				},
			},
		},
	}

	result := FilterComponentsByDestPath(alpineBOM, []string{"/usr/bin/curl"}, "/app/tools/curl")

	require.NotNil(t, result)
	assert.Equal(t, 1, GetComponentsCount(result))

	components := GetComponents(result)
	assert.Equal(t, "curl", components[0].Name)
	assert.Equal(t, "8.5.0-r0", components[0].Version)
	assert.Equal(t, "/app/tools/curl", GetLocationPath(components[0]))

	assert.NotNil(t, components[0].Properties)
	found := false
	for _, prop := range *components[0].Properties {
		if prop.Name == "syft:package:type" && prop.Value == "apk" {
			found = true
			break
		}
	}
	assert.True(t, found, "syft:package:type property should be preserved")
}

func TestFilterComponentsByDestPath_DirectoryCopy(t *testing.T) {
	alpineBOM := &cdx.BOM{
		BOMFormat:   "CycloneDX",
		SpecVersion: cdx.SpecVersion1_6,
		Components: &[]cdx.Component{
			{
				Name:    "ca-certificates",
				Version: "20230506-r0",
				Properties: &[]cdx.Property{
					{Name: SyftLocationPathProperty, Value: "/etc/ssl/certs/ca-certificates.crt"},
				},
			},
			{
				Name:    "openssl-config",
				Version: "3.1.4-r0",
				Properties: &[]cdx.Property{
					{Name: SyftLocationPathProperty, Value: "/etc/ssl/openssl.cnf"},
				},
			},
			{
				Name:    "unrelated-package",
				Version: "1.0.0",
				Properties: &[]cdx.Property{
					{Name: SyftLocationPathProperty, Value: "/usr/bin/tool"},
				},
			},
		},
	}

	result := FilterComponentsByDestPath(alpineBOM, []string{"/etc/ssl/"}, "/copied/ssl/")

	require.NotNil(t, result)
	assert.Equal(t, 2, GetComponentsCount(result))

	components := GetComponents(result)
	paths := make(map[string]string)
	for _, c := range components {
		paths[c.Name] = GetLocationPath(c)
	}

	assert.Equal(t, "/copied/ssl/certs/ca-certificates.crt", paths["ca-certificates"])
	assert.Equal(t, "/copied/ssl/openssl.cnf", paths["openssl-config"])
}
