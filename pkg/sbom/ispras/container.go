package ispras

import (
	"context"
	"fmt"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/samber/lo"

	"github.com/werf/werf/v2/pkg/sbom/cyclonedxutil"
)

var _ Assembler = (*ContainerAssembler)(nil)

type ContainerAssembler struct{}

// Assemble wraps the components of every image into a container component
// before merging, so that identical packages coming from different images stay
// in their own container instead of collapsing into a single entry, and the BOM
// refs namespaced per image keep matching the merged dependency graph. The
// image's own root component is kept inside its container: the ISPRAS checker
// binds a container's GOST values to the maximum over its content, so an image
// declared accessible needs a component carrying that value below the container.
func (a *ContainerAssembler) Assemble(_ context.Context, images []*ImageSBOM, meta ProductMeta) (*cdx.BOM, error) {
	wrapped := make([]*cdx.BOM, 0, len(images))
	for _, img := range images {
		imgBOM, err := cyclonedxutil.CloneBOM(img.BOM)
		if err != nil {
			return nil, fmt.Errorf("clone BOM of image %q: %w", img.Name, err)
		}

		container := cdx.Component{BOMRef: img.Name, Type: cdx.ComponentTypeContainer, Name: img.Name}
		container.ExternalReferences = imgBOM.ExternalReferences
		container.Properties = imgBOM.Properties

		imgComponents := lo.FromPtr(imgBOM.Components)
		if imgBOM.Metadata != nil && imgBOM.Metadata.Component != nil {
			root := *imgBOM.Metadata.Component
			container.Version = root.Version
			imgComponents = append([]cdx.Component{root}, imgComponents...)
		}

		setMissingGOSTOnComponent(&container, img.GOST)

		if len(imgComponents) > 0 {
			container.Components = &imgComponents
		}

		imgBOM.Components = &[]cdx.Component{container}
		wrapped = append(wrapped, imgBOM)
	}

	result, err := cyclonedxutil.MergeBOMs(nil, cyclonedxutil.MergeOpts{
		ImportBOMs:        wrapped,
		PreserveBOMRefs:   true,
		IsolateComponents: true,
	})
	if err != nil {
		return nil, fmt.Errorf("merge image BOMs: %w", err)
	}

	result.Metadata = buildProductMetadata(meta)

	return result, nil
}
