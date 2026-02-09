package sbom

import (
	"strings"
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"
)

func TestMergeBOMs_ConcatenatesComponentsInOrder(t *testing.T) {
	baseBOM := &cdx.BOM{
		Components: &[]cdx.Component{
			{Name: "base-comp-1", Version: "1.0.0"},
			{Name: "base-comp-2", Version: "2.0.0"},
		},
	}

	importBOM1 := &cdx.BOM{
		Components: &[]cdx.Component{
			{Name: "import1-comp", Version: "1.0.0"},
		},
	}

	importBOM2 := &cdx.BOM{
		Components: &[]cdx.Component{
			{Name: "import2-comp", Version: "1.0.0"},
		},
	}

	fragmentBOM := &cdx.BOM{
		Components: &[]cdx.Component{
			{Name: "fragment-comp", Version: "1.0.0"},
		},
	}

	targetBOM := &cdx.BOM{
		Components: &[]cdx.Component{
			{Name: "target-comp", Version: "1.0.0"},
		},
	}

	result := MergeBOMs(targetBOM, MergeOpts{
		BaseBOM:     baseBOM,
		ImportBOMs:  []*cdx.BOM{importBOM1, importBOM2},
		FragmentBOM: fragmentBOM,
	})

	if result.Components == nil {
		t.Fatal("expected components to be non-nil")
	}

	components := *result.Components
	if len(components) != 6 {
		t.Fatalf("expected 6 components, got %d", len(components))
	}

	expectedOrder := []string{"base-comp-1", "base-comp-2", "import1-comp", "import2-comp", "fragment-comp", "target-comp"}
	for i, expected := range expectedOrder {
		if components[i].Name != expected {
			t.Errorf("component %d: expected %q, got %q", i, expected, components[i].Name)
		}
	}
}

func TestMergeBOMs_TakesMetadataFromTarget(t *testing.T) {
	baseBOM := &cdx.BOM{
		Metadata: &cdx.Metadata{
			Component: &cdx.Component{Name: "base-metadata-component"},
		},
		Components: &[]cdx.Component{},
	}

	targetBOM := &cdx.BOM{
		Metadata: &cdx.Metadata{
			Component: &cdx.Component{Name: "target-metadata-component"},
		},
		Components: &[]cdx.Component{},
	}

	result := MergeBOMs(targetBOM, MergeOpts{
		BaseBOM: baseBOM,
	})

	if result.Metadata == nil {
		t.Fatal("expected metadata to be non-nil")
	}

	if result.Metadata.Component == nil {
		t.Fatal("expected metadata.component to be non-nil")
	}

	if result.Metadata.Component.Name != "target-metadata-component" {
		t.Errorf("expected metadata from target, got %q", result.Metadata.Component.Name)
	}
}

func TestMergeBOMs_SetsCorrectBOMFields(t *testing.T) {
	targetBOM := &cdx.BOM{
		Components: &[]cdx.Component{},
	}

	result := MergeBOMs(targetBOM, MergeOpts{})

	if result.BOMFormat != cdx.BOMFormat {
		t.Errorf("expected bomFormat %q, got %q", cdx.BOMFormat, result.BOMFormat)
	}

	if result.SpecVersion != cdx.SpecVersion1_6 {
		t.Errorf("expected specVersion 1.6, got %s", result.SpecVersion)
	}

	if result.Version != 1 {
		t.Errorf("expected version 1, got %d", result.Version)
	}

	if !strings.HasPrefix(result.SerialNumber, "urn:uuid:") {
		t.Errorf("expected serialNumber to start with 'urn:uuid:', got %q", result.SerialNumber)
	}

	if result.Dependencies != nil {
		t.Error("expected dependencies to be nil")
	}
}

func TestMergeBOMs_GeneratesNewSerialNumber(t *testing.T) {
	targetBOM := &cdx.BOM{
		SerialNumber: "urn:uuid:old-serial-number",
		Components:   &[]cdx.Component{},
	}

	result := MergeBOMs(targetBOM, MergeOpts{})

	if result.SerialNumber == targetBOM.SerialNumber {
		t.Error("expected new serial number to be generated")
	}

	if !strings.HasPrefix(result.SerialNumber, "urn:uuid:") {
		t.Errorf("expected serial number to start with 'urn:uuid:', got %q", result.SerialNumber)
	}
}

func TestMergeBOMs_HandlesNilTarget(t *testing.T) {
	baseBOM := &cdx.BOM{
		Components: &[]cdx.Component{
			{Name: "base-comp", Version: "1.0.0"},
		},
	}

	result := MergeBOMs(nil, MergeOpts{
		BaseBOM: baseBOM,
	})

	if result.Components == nil {
		t.Fatal("expected components to be non-nil")
	}

	components := *result.Components
	if len(components) != 1 {
		t.Fatalf("expected 1 component, got %d", len(components))
	}

	if result.Metadata != nil {
		t.Error("expected metadata to be nil when target is nil")
	}
}

func TestMergeBOMs_HandlesNilBOMs(t *testing.T) {
	result := MergeBOMs(nil, MergeOpts{
		BaseBOM:     nil,
		ImportBOMs:  nil,
		FragmentBOM: nil,
	})

	if result.Components == nil {
		t.Fatal("expected components to be non-nil")
	}

	if len(*result.Components) != 0 {
		t.Errorf("expected 0 components, got %d", len(*result.Components))
	}
}

func TestMergeBOMs_NoDuplication(t *testing.T) {
	duplicateComp := cdx.Component{Name: "duplicate-comp", Version: "1.0.0"}

	baseBOM := &cdx.BOM{
		Components: &[]cdx.Component{duplicateComp},
	}

	targetBOM := &cdx.BOM{
		Components: &[]cdx.Component{duplicateComp},
	}

	result := MergeBOMs(targetBOM, MergeOpts{
		BaseBOM: baseBOM,
	})

	components := *result.Components
	if len(components) != 2 {
		t.Fatalf("expected 2 components (no deduplication), got %d", len(components))
	}
}

func TestBOMChecksum_ReturnsConsistentHash(t *testing.T) {
	bom := &cdx.BOM{
		BOMFormat:   cdx.BOMFormat,
		SpecVersion: cdx.SpecVersion1_6,
		Version:     1,
		Components: &[]cdx.Component{
			{Name: "test-comp", Version: "1.0.0"},
		},
	}

	checksum1 := BOMChecksum(bom)
	checksum2 := BOMChecksum(bom)

	if checksum1 != checksum2 {
		t.Error("expected consistent checksum for same BOM")
	}

	if checksum1 == "" {
		t.Error("expected non-empty checksum")
	}
}

func TestBOMChecksum_DifferentForDifferentBOMs(t *testing.T) {
	bom1 := &cdx.BOM{
		Components: &[]cdx.Component{
			{Name: "comp-1", Version: "1.0.0"},
		},
	}

	bom2 := &cdx.BOM{
		Components: &[]cdx.Component{
			{Name: "comp-2", Version: "1.0.0"},
		},
	}

	if BOMChecksum(bom1) == BOMChecksum(bom2) {
		t.Error("expected different checksums for different BOMs")
	}
}

func TestBOMChecksum_ReturnsEmptyForNil(t *testing.T) {
	if BOMChecksum(nil) != "" {
		t.Error("expected empty checksum for nil BOM")
	}
}

func TestToJSON_SerializesBOM(t *testing.T) {
	bom := &cdx.BOM{
		BOMFormat:   cdx.BOMFormat,
		SpecVersion: cdx.SpecVersion1_6,
		Version:     1,
		Components: &[]cdx.Component{
			{Name: "test-comp", Version: "1.0.0"},
		},
	}

	data, err := ToJSON(bom)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(data) == 0 {
		t.Error("expected non-empty JSON output")
	}
}

func TestMergeOpts_IsEmpty(t *testing.T) {
	tests := []struct {
		name     string
		opts     MergeOpts
		expected bool
	}{
		{
			name:     "empty opts",
			opts:     MergeOpts{},
			expected: true,
		},
		{
			name:     "with base BOM",
			opts:     MergeOpts{BaseBOM: &cdx.BOM{}},
			expected: false,
		},
		{
			name:     "with import BOMs",
			opts:     MergeOpts{ImportBOMs: []*cdx.BOM{{}}},
			expected: false,
		},
		{
			name:     "with fragment BOM",
			opts:     MergeOpts{FragmentBOM: &cdx.BOM{}},
			expected: false,
		},
		{
			name:     "with empty import slice",
			opts:     MergeOpts{ImportBOMs: []*cdx.BOM{}},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.opts.IsEmpty(); got != tt.expected {
				t.Errorf("IsEmpty() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestMergeOpts_Checksum(t *testing.T) {
	bom1 := &cdx.BOM{Components: &[]cdx.Component{{Name: "comp1"}}}
	bom2 := &cdx.BOM{Components: &[]cdx.Component{{Name: "comp2"}}}

	opts1 := MergeOpts{BaseBOM: bom1}
	opts2 := MergeOpts{BaseBOM: bom2}
	opts3 := MergeOpts{BaseBOM: bom1} // Same as opts1

	checksum1 := opts1.Checksum()
	checksum2 := opts2.Checksum()
	checksum3 := opts3.Checksum()

	if checksum1 == "" {
		t.Error("expected non-empty checksum")
	}

	if checksum1 == checksum2 {
		t.Error("expected different checksums for different BOMs")
	}

	if checksum1 != checksum3 {
		t.Error("expected same checksum for same BOMs")
	}
}

func TestMergeOpts_Checksum_Empty(t *testing.T) {
	opts := MergeOpts{}
	if opts.Checksum() != "" {
		t.Error("expected empty checksum for empty opts")
	}
}
