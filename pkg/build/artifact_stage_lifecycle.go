package build

import (
	"context"

	"github.com/werf/werf/v2/pkg/build/image"
	"github.com/werf/werf/v2/pkg/build/stage"
)

func runRestoredArtifactStages(ctx context.Context, img *image.Image, phase Phase) error {
	for _, stg := range img.GetStages() {
		if artifactStage, ok := stg.(interface {
			GetArtifactMetadata() *stage.ArtifactStageMetadata
		}); !ok || artifactStage.GetArtifactMetadata() == nil {
			continue
		}
		if err := phase.OnImageStage(ctx, img, stg); err != nil {
			return err
		}
	}
	return nil
}
