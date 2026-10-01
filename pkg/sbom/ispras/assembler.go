package ispras

import (
	"context"
	"fmt"
	"time"

	cdx "github.com/CycloneDX/cyclonedx-go"

	"github.com/werf/werf/v3/pkg/sbom/cyclonedxutil/gost"
)

type Assembler interface {
	Assemble(ctx context.Context, images []*ImageSBOM, meta ProductMeta) (*cdx.BOM, error)
}

func NewAssembler(format Format) (Assembler, error) {
	switch format {
	case FormatContainer:
		return &ContainerAssembler{}, nil
	case FormatOSS:
		return &OSSAssembler{}, nil
	default:
		return nil, fmt.Errorf("unknown format %q", format)
	}
}

func buildProductMetadata(ctx context.Context, meta ProductMeta, sourceLangs []string) *cdx.Metadata {
	metaComponent := &cdx.Component{
		Type:    cdx.ComponentTypeApplication,
		Name:    meta.AppName,
		Version: meta.AppVersion,
		Manufacturer: &cdx.OrganizationalEntity{
			Name: meta.Manufacturer,
		},
	}

	gost.SetComponentSourceLangs(ctx, metaComponent, sourceLangs)

	return &cdx.Metadata{
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Component: metaComponent,
	}
}

func imageBOMs(images []*ImageSBOM) []*cdx.BOM {
	boms := make([]*cdx.BOM, len(images))
	for i, img := range images {
		boms[i] = img.BOM
	}
	return boms
}

// validateImages rejects an image SBOM carrying a GOST value outside the
// accepted domain. Images built before the domain shrank still hold
// `security_function: indirect` in the registry, and a product must not
// inherit it.
func validateImages(images []*ImageSBOM) error {
	for _, img := range images {
		if err := gost.ValidateValues(img.BOM); err != nil {
			return fmt.Errorf("image %q: %w", img.Name, err)
		}
	}

	return nil
}
