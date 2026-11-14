package build

import (
	"context"

	"github.com/werf/werf/v3/pkg/build/stage"
	"github.com/werf/werf/v3/pkg/container_backend"
	"github.com/werf/werf/v3/pkg/container_backend/stage_builder"
)

func nativeStageServiceFiles(ctx context.Context, stg stage.Interface) []string {
	builder, ok := stg.GetStageImage().Builder.(*stage_builder.StageBuilder)
	if !ok {
		return nil
	}
	if builder.GetDockerfileBuilderImplementation() != nil || builder.GetDockerfileStageBuilderImplementation() != nil {
		return nil
	}
	if native := builder.GetStapelStageBuilderImplementation(); native != nil {
		return native.SBOMServiceFiles(ctx)
	}
	if legacy := builder.GetLegacyStapelStageBuilderImplmentation(); legacy != nil {
		if provider, ok := legacy.Container().(container_backend.SBOMServiceFilesProvider); ok {
			return provider.SBOMServiceFiles(ctx)
		}
	}
	return nil
}
