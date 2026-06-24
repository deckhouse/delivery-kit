package stage

import (
	"context"

	"github.com/werf/common-go/pkg/util"
	"github.com/werf/werf/v2/pkg/build/builder"
	"github.com/werf/werf/v2/pkg/config"
	"github.com/werf/werf/v2/pkg/container_backend"
)

type PackagesStage struct {
	*UserWithGitPatchStage
}

func GeneratePackagesStage(ctx context.Context, imageBaseConfig *config.StapelImageBase, gitPatchStageOptions *NewGitPatchStageOptions, baseStageOptions *BaseStageOptions) *PackagesStage {
	b := getBuilder(imageBaseConfig, baseStageOptions)
	if b != nil && !b.IsPackagesEmpty(ctx) {
		return newPackagesStage(b, gitPatchStageOptions, baseStageOptions)
	}

	return nil
}

func newPackagesStage(builder builder.Builder, gitPatchStageOptions *NewGitPatchStageOptions, baseStageOptions *BaseStageOptions) *PackagesStage {
	opts := *baseStageOptions
	opts.NeedsNetwork = true
	s := &PackagesStage{}
	s.UserWithGitPatchStage = newUserWithGitPatchStage(builder, Packages, gitPatchStageOptions, &opts)
	return s
}

func (s *PackagesStage) GetDependencies(ctx context.Context, c Conveyor, cb container_backend.ContainerBackend, prevImage, prevBuiltImage *StageImage, buildContextArchive container_backend.BuildContextArchiver) (string, error) {
	stageDependenciesChecksum, err := s.getStageDependenciesChecksum(ctx, c, Packages)
	if err != nil {
		return "", err
	}

	return util.Sha256Hash(s.builder.PackagesChecksum(ctx), stageDependenciesChecksum), nil
}

func (s *PackagesStage) PrepareImage(ctx context.Context, c Conveyor, cb container_backend.ContainerBackend, prevBuiltImage, stageImage *StageImage, buildContextArchive container_backend.BuildContextArchiver) error {
	if err := s.UserWithGitPatchStage.PrepareImage(ctx, c, cb, prevBuiltImage, stageImage, nil); err != nil {
		return err
	}

	if err := s.builder.Packages(ctx, cb, stageImage.Builder, c.UseLegacyStapelBuilder(cb)); err != nil {
		return err
	}

	return nil
}
