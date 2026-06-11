package stage

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/werf/common-go/pkg/util"
	"github.com/werf/werf/v2/pkg/config"
	"github.com/werf/werf/v2/pkg/container_backend"
)

func GeneratePackagesInstallStage(_ context.Context, imageBaseConfig *config.StapelImageBase, baseStageOptions *BaseStageOptions, projectDir string) *PackagesInstallStage {
	if len(imageBaseConfig.Packages) == 0 {
		return nil
	}

	var resolvedPackages []string
	seen := map[string]bool{}

	for _, pkg := range imageBaseConfig.Packages {
		if pkg.Type != config.PackagesDirectiveTypeOSPM {
			continue
		}

		if len(pkg.Spec.Packages) > 0 {
			for _, name := range pkg.Spec.Packages {
				name = strings.TrimSpace(name)
				if name != "" && !seen[name] {
					seen[name] = true
					resolvedPackages = append(resolvedPackages, name)
				}
			}
		}

		if pkg.Spec.FilePath != "" {
			fullPath := filepath.Join(projectDir, pkg.Spec.FilePath)
			data, err := os.ReadFile(fullPath)
			if err != nil {
				panic(fmt.Sprintf("packages: unable to read file %q: %v", pkg.Spec.FilePath, err))
			}
			lines := strings.Split(string(data), "\n")
			for _, line := range lines {
				line = strings.TrimSpace(line)
				if line != "" && !seen[line] {
					seen[line] = true
					resolvedPackages = append(resolvedPackages, line)
				}
			}
		}
	}

	if len(resolvedPackages) == 0 {
		return nil
	}

	sort.Strings(resolvedPackages)

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
