package sbom

import (
	"context"
	"fmt"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/google/go-containerregistry/pkg/v1/tarball"

	"github.com/werf/logboek"
)

type CopyFromEntry struct {
	SourceImageRef string
	SourcePaths    []string
	DestPath       string
}

// ExtractAndFilterSBOM extracts SBOM from an image and filters it by the COPY paths.
// Returns the original BOM and the filtered BOM containing only components matching the copied paths.
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

	logboek.Context(ctx).Debug().LogF("Filtered SBOM: %d components from %d total\n", GetComponentsCount(filteredBOM), GetComponentsCount(originalBOM))

	return originalBOM, filteredBOM, nil
}
