package stage

import (
	"context"
	"fmt"
	"strings"

	"github.com/werf/common-go/pkg/util"
	"github.com/werf/werf/v2/pkg/config"
	"github.com/werf/werf/v2/pkg/container_backend"
)

func GeneratePackagesInstallStage(_ context.Context, imageBaseConfig *config.StapelImageBase, baseStageOptions *BaseStageOptions) *PackagesInstallStage {
	var resolvedPackages []string
	for _, pkg := range imageBaseConfig.Packages {
		if pkg.Type != config.PackagesDirectiveTypeOSPM {
			continue
		}
		resolvedPackages = append(resolvedPackages, pkg.Spec.Packages...)
	}

	if len(resolvedPackages) == 0 {
		return nil
	}

	s := &PackagesInstallStage{}
	s.resolvedPackages = resolvedPackages
	s.BaseStage = NewBaseStage(PackagesInstall, baseStageOptions)

	return s
}

type PackagesInstallStage struct {
	*BaseStage

	resolvedPackages []string
}

func (s *PackagesInstallStage) GetDependencies(_ context.Context, _ Conveyor, _ container_backend.ContainerBackend, _, _ *StageImage, _ container_backend.BuildContextArchiver) (string, error) {
	return util.Sha256Hash(s.resolvedPackages...), nil
}

func (s *PackagesInstallStage) PrepareImage(ctx context.Context, c Conveyor, cb container_backend.ContainerBackend, prevBuiltImage, stageImage *StageImage, _ container_backend.BuildContextArchiver) error {
	if err := s.BaseStage.PrepareImage(ctx, c, cb, prevBuiltImage, stageImage, nil); err != nil {
		return fmt.Errorf("error preparing base stage: %w", err)
	}

	installCmd := "pm install " + strings.Join(s.resolvedPackages, " ")

	if c.UseLegacyStapelBuilder(cb) {
		stageImage.Builder.LegacyStapelStageBuilder().BuilderContainer().AddRunCommands(installCmd)
	} else {
		stageImage.Builder.StapelStageBuilder().AddCommands(installCmd)
	}

	return nil
}
