package ispras

import (
	"context"
	"fmt"
	"time"

	cdx "github.com/CycloneDX/cyclonedx-go"
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

func buildProductMetadata(meta ProductMeta) *cdx.Metadata {
	metaComponent := &cdx.Component{
		Type:    cdx.ComponentTypeApplication,
		Name:    meta.AppName,
		Version: meta.AppVersion,
		Manufacturer: &cdx.OrganizationalEntity{
			Name: meta.Manufacturer,
		},
	}

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
