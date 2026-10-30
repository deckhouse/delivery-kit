package build

import (
	"context"
	"encoding/json"
	"fmt"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/samber/lo"
	"github.com/werf/logboek"

	"github.com/werf/werf/v3/pkg/build/stage"
	imagePkg "github.com/werf/werf/v3/pkg/image"
	"github.com/werf/werf/v3/pkg/sbom/nativegate"
)

// importScopeBackend is the copy backend the stage applied its imports with, as that
// stage recorded it when it was built.
//
// The include and exclude paths of one import mean different things to the two backends,
// so which of them copied decides what the import carried. The run reading this is not
// necessarily the run that did the copying: a stage reused from the cache was built by
// another one, possibly with the other builder, and the backend of the current run would
// then answer for a copy it never performed.
func importScopeBackend(stg stage.Interface) (nativegate.ImportBackend, error) {
	stageImage := stg.GetStageImage()
	if stageImage == nil || stageImage.Image == nil || stageImage.Image.GetStageDesc() == nil || stageImage.Image.GetStageDesc().Info == nil {
		return "", fmt.Errorf("no-data: stage %s carries no built stage the import copy backend could be read from", stg.Name())
	}
	var record sbomStageRecord
	if err := json.Unmarshal([]byte(stageImage.Image.GetStageDesc().Info.Labels[imagePkg.WerfSBOMStageLabel]), &record); err != nil {
		return "", fmt.Errorf("no-data: read the SBOM stage record of %s: %w", stg.Name(), err)
	}
	if record.Stage != stg.Name() {
		return "", fmt.Errorf("no-data: the SBOM stage record of %s belongs to stage %s", stg.Name(), record.Stage)
	}
	switch record.ImportBackend {
	case "copy-recurse":
		return nativegate.ImportBackendCopyRecurse, nil
	case "rsync":
		return nativegate.ImportBackendRsync, nil
	}

	return "", fmt.Errorf("no-data: stage %s records no import copy backend", stg.Name())
}

// scopeImportBOM answers what an import source contributes to the image that imports it:
// the components of the source's own SBOM that it says occur, in the source image, at a
// path at least one of the import directives carries.
//
// An import copies a part of another image. The document of that other image describes
// the whole of it - the toolchain it was built with, the sources it compiled, the
// packages of an environment none of which this image received - and a component whose
// every occurrence stands outside the copied scope is a statement about the donor, not
// about this image. A component the donor states no whereabouts of at all is such a
// statement too: nothing ties it to anything this image holds.
//
// What survives is unchanged, occurrences included: where a kept component sits in this
// image is settled by the verification, which reads both snapshots, and overwriting the
// donor's paths from a lexical mapping here would only put a guess in their place.
func scopeImportBOM(ctx context.Context, bom *cdx.BOM, scopes []nativegate.ImportScope) (*cdx.BOM, error) {
	if bom == nil {
		return nil, nil
	}
	if len(scopes) == 0 {
		return nil, fmt.Errorf("no-data: an import source SBOM is read for no import directive")
	}
	carried := func(path string) (bool, error) {
		for _, scope := range scopes {
			carries, err := nativegate.ImportCarries(scope, path)
			if err != nil {
				return false, err
			}
			if carries {
				return true, nil
			}
		}

		return false, nil
	}

	scoped := *bom
	components, err := scopedComponents(ctx, bom.Components, carried)
	if err != nil {
		return nil, err
	}
	scoped.Components = components
	if bom.Metadata != nil && bom.Metadata.Component != nil {
		metadata := *bom.Metadata
		component := *bom.Metadata.Component
		nested, err := scopedComponents(ctx, component.Components, carried)
		if err != nil {
			return nil, err
		}
		component.Components = nested
		metadata.Component = &component
		scoped.Metadata = &metadata
	}
	scoped.Dependencies = scopedDependencies(bom.Dependencies, &scoped)

	return &scoped, nil
}

func scopedComponents(ctx context.Context, components *[]cdx.Component, carried func(path string) (bool, error)) (*[]cdx.Component, error) {
	if components == nil {
		return nil, nil
	}
	kept := make([]cdx.Component, 0, len(*components))
	for _, comp := range *components {
		// A component holding the ones below it keeps whatever of them is carried,
		// and stays itself as long as anything it holds does.
		nested, err := scopedComponents(ctx, comp.Components, carried)
		if err != nil {
			return nil, err
		}
		comp.Components = nested
		occurs, err := occursInScope(comp, carried)
		if err != nil {
			return nil, err
		}
		if !occurs && nested == nil {
			// A scanner states where it found a component only when it read it out
			// of a file; one it named from a manifest of the donor - a lockfile, an
			// installed-package database - carries no whereabouts at all, and this
			// import is not a reason to believe this image received it.
			logboek.Context(ctx).Debug().LogF("SBOM import scope: drop %s %s, no occurrence the import carries\n", comp.Name, comp.Version)

			continue
		}
		kept = append(kept, comp)
	}
	if len(kept) == 0 {
		return nil, nil
	}

	return &kept, nil
}

func occursInScope(comp cdx.Component, carried func(path string) (bool, error)) (bool, error) {
	if comp.Evidence == nil || comp.Evidence.Occurrences == nil {
		return false, nil
	}
	for _, occurrence := range *comp.Evidence.Occurrences {
		if occurrence.Location == "" {
			continue
		}
		carries, err := carried(occurrence.Location)
		if err != nil {
			return false, err
		}
		if carries {
			return true, nil
		}
	}

	return false, nil
}

// scopedDependencies keeps the edges between the components that remain. An edge to a
// component this import does not contribute names nothing of this image.
func scopedDependencies(dependencies *[]cdx.Dependency, scoped *cdx.BOM) *[]cdx.Dependency {
	if dependencies == nil {
		return nil
	}
	refs := map[string]struct{}{}
	var collect func(components *[]cdx.Component)
	collect = func(components *[]cdx.Component) {
		for _, comp := range lo.FromPtr(components) {
			refs[comp.BOMRef] = struct{}{}
			collect(comp.Components)
		}
	}
	collect(scoped.Components)
	if scoped.Metadata != nil && scoped.Metadata.Component != nil {
		refs[scoped.Metadata.Component.BOMRef] = struct{}{}
		collect(scoped.Metadata.Component.Components)
	}

	kept := make([]cdx.Dependency, 0, len(*dependencies))
	for _, dependency := range *dependencies {
		if _, known := refs[dependency.Ref]; !known {
			continue
		}
		if dependency.Dependencies != nil {
			depends := lo.Filter(*dependency.Dependencies, func(ref string, _ int) bool {
				_, known := refs[ref]

				return known
			})
			dependency.Dependencies = &depends
		}
		kept = append(kept, dependency)
	}
	if len(kept) == 0 {
		return nil
	}

	return &kept
}
