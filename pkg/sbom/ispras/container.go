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

func (a *ContainerAssembler) Assemble(_ context.Context, images []*ImageSBOM, meta ProductMeta) (*cdx.BOM, error) {
	dependencies := imageDependencies(images)

	result, err := cyclonedxutil.MergeBOMs(nil, cyclonedxutil.MergeOpts{
		ImportBOMs: imageBOMs(images),
	})
	if err != nil {
		return nil, fmt.Errorf("merge image BOMs: %w", err)
	}

	var containers []cdx.Component
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

		containers = append(containers, container)
	}
	if len(containers) > 0 {
		result.Components = &containers
	} else {
		result.Components = nil
	}
	if len(dependencies) > 0 {
		result.Dependencies = &dependencies
	} else {
		result.Dependencies = nil
	}

	result.Metadata = buildProductMetadata(meta)

	return result, nil
}

// imageDependencies copies the per-image dependency graphs before MergeBOMs
// rewrites their refs in place; the container tree keeps the original
// namespaced component refs, so the graph must keep them too.
func imageDependencies(images []*ImageSBOM) []cdx.Dependency {
	var dependencies []cdx.Dependency
	for _, img := range images {
		for _, dep := range lo.FromPtr(img.BOM.Dependencies) {
			copied := cdx.Dependency{Ref: dep.Ref}
			if dep.Dependencies != nil {
				copied.Dependencies = lo.ToPtr(append([]string(nil), *dep.Dependencies...))
			}
			if dep.Provides != nil {
				copied.Provides = lo.ToPtr(append([]string(nil), *dep.Provides...))
			}
			dependencies = append(dependencies, copied)
		}
	}

	return dependencies
}
