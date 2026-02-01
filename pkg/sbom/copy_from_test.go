package sbom

import (
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSBOMCollector(t *testing.T) {
	bom1 := &cdx.BOM{
		BOMFormat:   "CycloneDX",
		SpecVersion: cdx.SpecVersion1_6,
		Components:  &[]cdx.Component{{Name: "curl"}},
	}

	bom2 := &cdx.BOM{
		BOMFormat:   "CycloneDX",
		SpecVersion: cdx.SpecVersion1_6,
		Components:  &[]cdx.Component{{Name: "bash"}},
	}

	emptyBOM := &cdx.BOM{
		BOMFormat:  "CycloneDX",
		Components: &[]cdx.Component{},
	}

	t.Run("new collector is empty", func(t *testing.T) {
		c := NewSBOMCollector()
		assert.False(t, c.HasEntries())
		assert.Equal(t, 0, c.Count())
		assert.Nil(t, c.Merge())
	})

	t.Run("add and merge", func(t *testing.T) {
		c := NewSBOMCollector()
		c.Add(bom1)
		c.Add(bom2)

		assert.True(t, c.HasEntries())
		assert.Equal(t, 2, c.Count())

		merged := c.Merge()
		require.NotNil(t, merged)
		assert.Equal(t, 2, GetComponentsCount(merged))
	})

	t.Run("ignores nil", func(t *testing.T) {
		c := NewSBOMCollector()
		c.Add(nil)
		assert.False(t, c.HasEntries())
	})

	t.Run("ignores empty BOM", func(t *testing.T) {
		c := NewSBOMCollector()
		c.Add(emptyBOM)
		assert.False(t, c.HasEntries())
	})
}

func TestCopyFromEntry(t *testing.T) {
	entry := CopyFromEntry{
		SourceImageRef: "registry.example.com/image:v1",
		SourcePaths:    []string{"/usr/bin/curl"},
		DestPath:       "/bin/curl",
	}

	assert.Equal(t, "registry.example.com/image:v1", entry.SourceImageRef)
	assert.Equal(t, []string{"/usr/bin/curl"}, entry.SourcePaths)
	assert.Equal(t, "/bin/curl", entry.DestPath)
}

func TestCopyFromSBOMResult(t *testing.T) {
	originalBOM := &cdx.BOM{Components: &[]cdx.Component{{Name: "curl"}}}
	filteredBOM := &cdx.BOM{Components: &[]cdx.Component{{Name: "curl"}}}

	result := CopyFromSBOMResult{
		CopyFromEntry: CopyFromEntry{
			SourceImageRef: "registry.example.com/image:v1",
			SourcePaths:    []string{"/usr/bin/curl"},
			DestPath:       "/bin/curl",
		},
		OriginalSBOM: originalBOM,
		FilteredSBOM: filteredBOM,
	}

	assert.Equal(t, "registry.example.com/image:v1", result.SourceImageRef)
	assert.NotNil(t, result.OriginalSBOM)
	assert.NotNil(t, result.FilteredSBOM)
}
