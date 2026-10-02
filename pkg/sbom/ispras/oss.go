package ispras

import (
	"context"
	"fmt"

	cdx "github.com/CycloneDX/cyclonedx-go"

	"github.com/werf/werf/v3/pkg/sbom/cyclonedxutil"
)

var _ Assembler = (*OSSAssembler)(nil)

type OSSAssembler struct{}

func (a *OSSAssembler) Assemble(ctx context.Context, images []*ImageSBOM, meta ProductMeta) (*cdx.BOM, error) {
	if err := validateImages(images); err != nil {
		return nil, err
	}

	result, err := cyclonedxutil.MergeBOMs(ctx, nil, cyclonedxutil.MergeOpts{
		ImportBOMs: imageBOMs(images),
	})
	if err != nil {
		return nil, fmt.Errorf("merge image BOMs: %w", err)
	}

	result.Metadata = buildProductMetadata(ctx, meta, aggregateSourceLangs(ctx, images))

	return result, nil
}
