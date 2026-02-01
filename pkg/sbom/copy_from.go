package sbom

import (
	"context"
	"fmt"
	"io"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/google/go-containerregistry/pkg/v1/tarball"

	"github.com/werf/logboek"
)

// CopyFromEntry represents data for a COPY --from instruction.
type CopyFromEntry struct {
	// SourceImageRef is the reference to the source image (COPY --from=<image>).
	SourceImageRef string
	// SourcePaths are the source paths from the COPY instruction.
	SourcePaths []string
	// DestPath is the destination path from the COPY instruction.
	DestPath string
}

// CopyFromSBOMResult contains SBOM processing results for a COPY --from instruction.
type CopyFromSBOMResult struct {
	CopyFromEntry
	// OriginalSBOM is the original SBOM from the source image.
	OriginalSBOM *cdx.BOM
	// FilteredSBOM is the SBOM filtered by the copied paths.
	FilteredSBOM *cdx.BOM
}

// SBOMCollector collects and merges filtered SBOMs from multiple sources.
type SBOMCollector struct {
	entries []*cdx.BOM
}

// NewSBOMCollector creates a new SBOMCollector.
func NewSBOMCollector() *SBOMCollector {
	return &SBOMCollector{
		entries: make([]*cdx.BOM, 0),
	}
}

// Add adds a filtered SBOM to the collector.
// Nil BOMs and BOMs with no components are ignored.
func (c *SBOMCollector) Add(bom *cdx.BOM) {
	if bom != nil && GetComponentsCount(bom) > 0 {
		c.entries = append(c.entries, bom)
	}
}

// Merge returns a merged SBOM from all collected entries.
func (c *SBOMCollector) Merge() *cdx.BOM {
	return MergeSBOMs(c.entries...)
}

// HasEntries returns true if there are any collected SBOMs.
func (c *SBOMCollector) HasEntries() bool {
	return len(c.entries) > 0
}

// Count returns the number of collected SBOMs.
func (c *SBOMCollector) Count() int {
	return len(c.entries)
}

// ExtractAndFilterSBOM extracts SBOM from an image and filters it by the COPY paths.
// opener is a function that returns a ReadCloser for the SBOM image tarball.
// Returns the original BOM and the filtered BOM.
func ExtractAndFilterSBOM(ctx context.Context, opener tarball.Opener, srcPaths []string, dstPath string) (*cdx.BOM, *cdx.BOM, error) {
	// Extract SBOM artifact from image
	sbomData, err := FindSingleSbomArtifact(opener)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to find SBOM artifact: %w", err)
	}

	// Parse SBOM
	originalBOM, err := ParseCycloneDXBOM(sbomData)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to parse SBOM: %w", err)
	}

	// Filter components by destination path
	filteredBOM := FilterComponentsByDestPath(originalBOM, srcPaths, dstPath)

	logboek.Context(ctx).Debug().LogF("Filtered SBOM: %d components from %d total\n",
		GetComponentsCount(filteredBOM), GetComponentsCount(originalBOM))

	return originalBOM, filteredBOM, nil
}

// SaveImageToStreamOpener creates a tarball.Opener from a save image to stream function.
func SaveImageToStreamOpener(saveFunc func() io.ReadCloser) tarball.Opener {
	return func() (io.ReadCloser, error) {
		return saveFunc(), nil
	}
}
