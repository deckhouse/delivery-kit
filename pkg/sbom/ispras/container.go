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
// container replaces the image's root component, taking over every reference to
// it.
func (a *ContainerAssembler) Assemble(_ context.Context, images []*ImageSBOM, meta ProductMeta) (*cdx.BOM, error) {
	wrapped := make([]*cdx.BOM, 0, len(images))
	for _, img := range images {
		imgBOM, err := cyclonedxutil.CloneBOM(img.BOM)
		if err != nil {
			return nil, fmt.Errorf("clone BOM of image %q: %w", img.Name, err)
		}

		container := cdx.Component{BOMRef: img.Name, Type: cdx.ComponentTypeContainer, Name: img.Name}

		if imgBOM.Metadata != nil && imgBOM.Metadata.Component != nil {
			root := imgBOM.Metadata.Component
			container = *root
			container.BOMRef = img.Name
			container.Type = cdx.ComponentTypeContainer
			container.Name = img.Name

			if root.BOMRef != "" {
				cyclonedxutil.RewriteRefs(imgBOM, map[string]string{root.BOMRef: img.Name})
			}
		}

		container.ExternalReferences = imgBOM.ExternalReferences
		container.Properties = imgBOM.Properties

		setMissingGOSTOnComponent(&container, img.GOST)

		imgComponents := lo.FromPtr(imgBOM.Components)
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
