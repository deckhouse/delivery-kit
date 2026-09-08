package ispras

import (
	"context"
	"fmt"

	cdx "github.com/CycloneDX/cyclonedx-go"

	"github.com/werf/werf/v2/pkg/sbom/cyclonedxutil"
)

var _ Assembler = (*OSSAssembler)(nil)

type OSSAssembler struct{}

func (a *OSSAssembler) Assemble(_ context.Context, images []*ImageSBOM, meta ProductMeta) (*cdx.BOM, error) {
	result, err := cyclonedxutil.MergeBOMs(nil, cyclonedxutil.MergeOpts{
		ImportBOMs: imageBOMs(images),
	})
	if err != nil {
		return nil, fmt.Errorf("merge image BOMs: %w", err)
	}

	result.Metadata = buildProductMetadata(meta)

	return result, nil
}
