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
// dependency edges of the image's root component are carried over to the
// container that replaces it.
func (a *ContainerAssembler) Assemble(_ context.Context, images []*ImageSBOM, meta ProductMeta) (*cdx.BOM, error) {
	wrapped := make([]*cdx.BOM, 0, len(images))
	for _, img := range images {
		container := cdx.Component{BOMRef: img.Name, Type: cdx.ComponentTypeContainer, Name: img.Name}

		if img.BOM.Metadata != nil && img.BOM.Metadata.Component != nil {
			container = *img.BOM.Metadata.Component
			container.BOMRef = img.Name
			container.Type = cdx.ComponentTypeContainer
			container.Name = img.Name
		}

		container.ExternalReferences = img.BOM.ExternalReferences
		container.Properties = img.BOM.Properties

		setMissingGOSTOnComponent(&container, img.GOST)

		imgComponents := lo.FromPtr(img.BOM.Components)
		if len(imgComponents) > 0 {
			container.Components = &imgComponents
		}

		imgBOM := *img.BOM
		imgBOM.Components = &[]cdx.Component{container}
		if img.BOM.Metadata != nil && img.BOM.Metadata.Component != nil && img.BOM.Metadata.Component.BOMRef != "" {
			imgBOM.Dependencies = rootDependenciesAs(img.BOM.Dependencies, img.BOM.Metadata.Component.BOMRef, img.Name)
		}
		wrapped = append(wrapped, &imgBOM)
	}

	result, err := cyclonedxutil.MergeBOMs(nil, cyclonedxutil.MergeOpts{
		ImportBOMs:      wrapped,
		PreserveBOMRefs: true,
	})
	if err != nil {
		return nil, fmt.Errorf("merge image BOMs: %w", err)
	}

	result.Metadata = buildProductMetadata(meta)

	return result, nil
}

func rootDependenciesAs(deps *[]cdx.Dependency, rootRef, newRef string) *[]cdx.Dependency {
	if deps == nil {
		return nil
	}

	result := make([]cdx.Dependency, len(*deps))
	for i, dep := range *deps {
		if dep.Ref == rootRef {
			dep.Ref = newRef
		}
		result[i] = dep
	}

	return &result
}
