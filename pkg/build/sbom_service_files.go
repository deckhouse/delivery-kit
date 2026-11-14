package build

import (
	"context"
	"slices"

	"github.com/werf/werf/v3/pkg/build/stage"
	"github.com/werf/werf/v3/pkg/container_backend"
	"github.com/werf/werf/v3/pkg/container_backend/stage_builder"
)

func nativeStageServiceFiles(ctx context.Context, stg stage.Interface) []string {
	builder, ok := stg.GetStageImage().Builder.(*stage_builder.StageBuilder)
	if !ok {
		return nil
	}
	var files []string
	if native := builder.GetStapelStageBuilderImplementation(); native != nil {
		files = append(files, native.SBOMServiceFiles(ctx)...)
	}
	if legacy := builder.GetLegacyStapelStageBuilderImplmentation(); legacy != nil {
		if provider, ok := legacy.Container().(container_backend.SBOMServiceFilesProvider); ok {
			files = append(files, provider.SBOMServiceFiles(ctx)...)
		}
	}
	slices.Sort(files)
	return slices.Compact(files)
}
