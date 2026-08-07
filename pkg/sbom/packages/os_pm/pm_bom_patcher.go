package os_pm

import (
	"context"
	"encoding/json"
	"fmt"

	cdx "github.com/CycloneDX/cyclonedx-go"

	"github.com/werf/logboek"
	"github.com/werf/werf/v2/pkg/container_backend"
	"github.com/werf/werf/v2/pkg/git_repo"
	"github.com/werf/werf/v2/pkg/sbom/cyclonedxutil"
)

type PMBOMPatcher struct {
	gitRepo          git_repo.GitRepo
	commit           string
	lockPath         string
	specPath         string
	containerBackend container_backend.ContainerBackend
	imageRef         string
}

func NewPMBOMPatcher(gitRepo git_repo.GitRepo, commit, lockPath, specPath string, containerBackend container_backend.ContainerBackend, imageRef string) *PMBOMPatcher {
	return &PMBOMPatcher{
		gitRepo:          gitRepo,
		commit:           commit,
		lockPath:         lockPath,
		specPath:         specPath,
		containerBackend: containerBackend,
		imageRef:         imageRef,
	}
}

func (p *PMBOMPatcher) Apply(ctx context.Context, bom *cdx.BOM) (*cdx.BOM, error) {
	if p.gitRepo == nil || p.commit == "" {
		return bom, nil
	}

	lockFileExists, err := p.gitRepo.IsCommitFileExist(ctx, p.commit, p.lockPath)
	if err != nil {
		return nil, fmt.Errorf("check pm.lock existence: %w", err)
	}

	if !lockFileExists {
		// T013: If pm.yaml exists but pm.lock is missing, fail with a clear error.
		specFileExists, err := p.gitRepo.IsCommitFileExist(ctx, p.commit, p.specPath)
		if err != nil {
			return nil, fmt.Errorf("check pm.yaml existence: %w", err)
		}
		if specFileExists {
			return nil, fmt.Errorf("pm.lock not found at %s. Run 'pm lock' in your repository to generate the lock file, commit it, and retry.", p.lockPath)
		}

		// No os-pm packages — nothing to do.
		logboek.Context(ctx).Debug().LogF("No pm.lock found at %s, skipping os-pm SBOM processing\n", p.lockPath)
		return bom, nil
	}

	content, err := p.gitRepo.ReadCommitFile(ctx, p.commit, p.lockPath)
	if err != nil {
		return nil, fmt.Errorf("read pm.lock: %w", err)
	}
	if len(content) == 0 {
		return bom, nil
	}

	pkgs, err := parsePmLockFile(content)
	if err != nil {
		return nil, fmt.Errorf("parse pm.lock: %w", err)
	}
	if len(pkgs) == 0 {
		return bom, nil
	}

	version, err := ReadContainerFactoryVersion(ctx, p.containerBackend, p.imageRef)
	if err != nil {
		// If the container factory version file does not exist in the base image,
		// proceed without the qualifier rather than failing the build.
		logboek.Context(ctx).Debug().LogF("read container factory version: %s (proceeding without qualifier)\n", err)
		version = ""
	}

	pmBOM := ConvertToCycloneDX(pkgs, version)
	if pmBOM == nil || pmBOM.Components == nil {
		return bom, nil
	}

	// Append PM components to the result BOM.
	if bom.Components == nil {
		bom.Components = pmBOM.Components
	} else {
		*bom.Components = append(*bom.Components, *pmBOM.Components...)
	}

	// Merge dependencies if present.
	if pmBOM.Dependencies != nil {
		if bom.Dependencies == nil {
			bom.Dependencies = pmBOM.Dependencies
		} else {
			*bom.Dependencies = append(*bom.Dependencies, *pmBOM.Dependencies...)
		}
	}

	cyclonedxutil.DedupBOM(bom)

	return bom, nil
}

// pmLockFile represents the top-level structure of pm.lock.
type pmLockFile struct {
	Packages map[string]PmPackageInfo `json:"packages"`
}

// parsePmLockFile parses a pm.lock JSON file, extracting the inner packages map.
// pm.lock has the format: {"metadata": {...}, "packages": {"curl": {...}, ...}}
func parsePmLockFile(data []byte) (map[string]PmPackageInfo, error) {
	var lock pmLockFile
	if err := json.Unmarshal(data, &lock); err != nil {
		return nil, fmt.Errorf("parse pm.lock file: %w", err)
	}

	return lock.Packages, nil
}
