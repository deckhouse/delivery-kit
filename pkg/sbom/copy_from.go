package sbom

import (
	"context"
	"fmt"
	"io"

	"github.com/google/go-containerregistry/pkg/v1/tarball"

	"github.com/werf/logboek"
)

// CopyFromSBOMInfo contains information about SBOM from COPY --from instruction.
type CopyFromSBOMInfo struct {
	// SourceImageRef is the reference to the source image.
	SourceImageRef string
	// SourcePaths are the source paths from the COPY instruction.
	SourcePaths []string
	// DestPath is the destination path in the target image.
	DestPath string
	// OriginalSBOM is the original SBOM from the source image.
	OriginalSBOM *CycloneDXBOM
	// FilteredSBOM is the SBOM filtered by the destination path.
	FilteredSBOM *CycloneDXBOM
}

// CopyFromSBOMCollector collects and filters SBOMs from COPY --from instructions.
type CopyFromSBOMCollector struct {
	entries []CopyFromSBOMInfo
}

// NewCopyFromSBOMCollector creates a new CopyFromSBOMCollector.
func NewCopyFromSBOMCollector() *CopyFromSBOMCollector {
	return &CopyFromSBOMCollector{
		entries: make([]CopyFromSBOMInfo, 0),
	}
}

// AddEntry adds a new COPY --from SBOM entry.
func (c *CopyFromSBOMCollector) AddEntry(entry CopyFromSBOMInfo) {
	c.entries = append(c.entries, entry)
}

// GetEntries returns all collected entries.
func (c *CopyFromSBOMCollector) GetEntries() []CopyFromSBOMInfo {
	return c.entries
}

// GetMergedFilteredSBOM returns a merged SBOM from all filtered entries.
func (c *CopyFromSBOMCollector) GetMergedFilteredSBOM() *CycloneDXBOM {
	boms := make([]*CycloneDXBOM, 0, len(c.entries))
	for _, entry := range c.entries {
		if entry.FilteredSBOM != nil && len(entry.FilteredSBOM.Components) > 0 {
			boms = append(boms, entry.FilteredSBOM)
		}
	}
	return MergeSBOMs(boms...)
}

// ExtractAndFilterSBOM extracts SBOM from an image and filters it by the COPY paths.
// opener is a function that returns a ReadCloser for the SBOM image tarball.
func ExtractAndFilterSBOM(ctx context.Context, opener tarball.Opener, srcPaths []string, dstPath string) (*CycloneDXBOM, *CycloneDXBOM, error) {
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
		len(filteredBOM.Components), len(originalBOM.Components))

	return originalBOM, filteredBOM, nil
}

// SaveImageToStreamOpener creates a tarball.Opener from a save image to stream function.
func SaveImageToStreamOpener(saveFunc func() io.ReadCloser) tarball.Opener {
	return func() (io.ReadCloser, error) {
		return saveFunc(), nil
	}
}
