package stage

import (
	"context"
	"fmt"
	"path"

	"github.com/werf/common-go/pkg/util"
	"github.com/werf/werf/v2/pkg/config"
	"github.com/werf/werf/v2/pkg/container_backend"
)

type PackageResolveStage struct {
	*BaseStage
	directive *config.PackagesDirective
	index     int
}

func GeneratePackageResolveStage(directive *config.PackagesDirective, index int, baseStageOptions *BaseStageOptions) *PackageResolveStage {
	if directive == nil {
		return nil
	}
	s := newPackageResolveStage(directive, index, baseStageOptions)
	if len(s.resolveCommands()) == 0 {
		return nil
	}
	return s
}

func newPackageResolveStage(directive *config.PackagesDirective, index int, baseStageOptions *BaseStageOptions) *PackageResolveStage {
	s := &PackageResolveStage{
		directive: directive,
		index:     index,
	}
	s.BaseStage = NewBaseStage(StageName(fmt.Sprintf("packageResolve%d", index)), baseStageOptions)
	return s
}

func (s *PackageResolveStage) Name() StageName {
	return StageName(fmt.Sprintf("packageResolve%d", s.index))
}

func (s *PackageResolveStage) SetGitMappings(gitMappings []*GitMapping) {
	s.BaseStage.SetGitMappings(gitMappings)

	lockfilePath := s.lockfilePath()
	if lockfilePath == "" {
		return
	}

	for _, gm := range gitMappings {
		if gm.StagesDependencies == nil {
			gm.StagesDependencies = make(map[StageName][]string)
		}
		gm.StagesDependencies[s.Name()] = append(gm.StagesDependencies[s.Name()], lockfilePath)
	}
}

func (s *PackageResolveStage) IsEmpty(ctx context.Context, c Conveyor, prevBuiltImage *StageImage) (bool, error) {
	return false, nil
}

func (s *PackageResolveStage) GetDependencies(ctx context.Context, c Conveyor, cb container_backend.ContainerBackend, prevImage, prevBuiltImage *StageImage, buildContextArchive container_backend.BuildContextArchiver) (string, error) {
	args := []string{string(s.directive.Type), s.lockfilePath()}

	for _, gitMapping := range s.gitMappings {
		checksum, err := gitMapping.StageDependenciesChecksum(ctx, c, s.Name())
		if err != nil {
			return "", fmt.Errorf("get lockfile checksum: %w", err)
		}
		if checksum != "" {
			args = append(args, checksum)
		}
	}

	return util.Sha256Hash(args...), nil
}

func (s *PackageResolveStage) PrepareImage(ctx context.Context, c Conveyor, cb container_backend.ContainerBackend, prevBuiltImage, stageImage *StageImage, buildContextArchive container_backend.BuildContextArchiver) error {
	if err := s.BaseStage.PrepareImage(ctx, c, cb, prevBuiltImage, stageImage, buildContextArchive); err != nil {
		return err
	}

	commands := s.resolveCommands()

	if c.UseLegacyStapelBuilder(cb) {
		stageImage.Builder.LegacyStapelStageBuilder().Container().AddRunCommands(commands...)
	}

	return nil
}

func (s *PackageResolveStage) resolveCommands() []string {
	switch s.directive.Type {
	case config.PackagesDirectiveTypeGoMod:
		return []string{fmt.Sprintf("cd %s && go mod download", s.directive.GoMod.Workdir)}
	default:
		return nil
	}
}

func (s *PackageResolveStage) lockfilePath() string {
	switch s.directive.Type {
	case config.PackagesDirectiveTypeGoMod:
		return path.Join(s.directive.GoMod.Workdir, s.directive.GoMod.Lock)
	default:
		return ""
	}
}
