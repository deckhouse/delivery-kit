package sbom

import (
	"context"
	"fmt"
	"io"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/google/go-containerregistry/pkg/v1/tarball"

	"github.com/werf/logboek"
)

type CopyFromEntry struct {
	SourceImageRef string
	SourcePaths    []string
	DestPath       string
}

type CopyFromSBOMResult struct {
	CopyFromEntry
	OriginalSBOM *cdx.BOM
	FilteredSBOM *cdx.BOM
}

type SBOMCollector struct {
	entries []*cdx.BOM
}

func NewSBOMCollector() *SBOMCollector {
	return &SBOMCollector{
		entries: make([]*cdx.BOM, 0),
	}
}

func (c *SBOMCollector) Add(bom *cdx.BOM) {
	if bom != nil && GetComponentsCount(bom) > 0 {
		c.entries = append(c.entries, bom)
	}
}

func (c *SBOMCollector) Merge() *cdx.BOM {
	return MergeSBOMs(c.entries...)
}

func (c *SBOMCollector) HasEntries() bool {
	return len(c.entries) > 0
}

func (c *SBOMCollector) Count() int {
	return len(c.entries)
}

func ExtractAndFilterSBOM(ctx context.Context, opener tarball.Opener, srcPaths []string, dstPath string) (*cdx.BOM, *cdx.BOM, error) {
	sbomData, err := FindSingleSbomArtifact(opener)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to find SBOM artifact: %w", err)
	}

	originalBOM, err := ParseCycloneDXBOM(sbomData)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to parse SBOM: %w", err)
	}

	filteredBOM := FilterComponentsByDestPath(originalBOM, srcPaths, dstPath)

	logboek.Context(ctx).Debug().LogF("Filtered SBOM: %d components from %d total\n",
		GetComponentsCount(filteredBOM), GetComponentsCount(originalBOM))

	return originalBOM, filteredBOM, nil
}

func SaveImageToStreamOpener(saveFunc func() io.ReadCloser) tarball.Opener {
	return func() (io.ReadCloser, error) {
		return saveFunc(), nil
	}
}
