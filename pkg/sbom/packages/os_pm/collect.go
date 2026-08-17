package os_pm

import (
	"context"
	"fmt"
	"strings"

	cdx "github.com/CycloneDX/cyclonedx-go"

	"github.com/werf/werf/v2/pkg/container_backend"
	"github.com/werf/werf/v2/pkg/sbom/cyclonedxutil"
)

const (
	CatalogerName               = "pm-cataloger"
	ContainerFactoryIndexPath   = "/var/lib/pm/index.json"
	ContainerFactoryVersionPath = "/var/lib/pm/container-factory-version"
)

func ReadContainerFactoryVersion(ctx context.Context, containerBackend container_backend.ContainerBackend, imageRef string) (string, error) {
	return readContainerFactoryVersion(ctx, containerBackend, imageRef)
}

func readContainerFactoryVersion(ctx context.Context, containerBackend container_backend.ContainerBackend, imageRef string) (string, error) {
	stdout, err := containerBackend.ReadFileFromImage(ctx, imageRef, ContainerFactoryVersionPath, container_backend.ReadFileFromImageOpts{})
	if err != nil {
		return "", fmt.Errorf("read %s from image %q: %w", ContainerFactoryVersionPath, imageRef, err)
	}

	version := strings.TrimSpace(string(stdout))
	if version == "" {
		return "", fmt.Errorf("%s is empty in image %q", ContainerFactoryVersionPath, imageRef)
	}

	return version, nil
}

func CollectAndMergeBOM(ctx context.Context, containerBackend container_backend.ContainerBackend, imageRef string, target *cdx.BOM) (*cdx.BOM, error) {
	pmBOM, err := CollectBOM(ctx, containerBackend, imageRef)
	if err != nil {
		return nil, fmt.Errorf("collect os-pm BOM: %w", err)
	}
	if pmBOM == nil {
		return target, nil
	}
	if target == nil {
		target = cyclonedxutil.NewBOM()
	}
	if pmBOM.Components != nil {
		if target.Components == nil {
			target.Components = pmBOM.Components
		} else {
			*target.Components = append(*target.Components, *pmBOM.Components...)
		}
	}
	if pmBOM.Dependencies != nil {
		if target.Dependencies == nil {
			target.Dependencies = pmBOM.Dependencies
		} else {
			*target.Dependencies = append(*target.Dependencies, *pmBOM.Dependencies...)
		}
	}
	cyclonedxutil.DedupBOM(target)
	return target, nil
}

func CollectBOM(ctx context.Context, containerBackend container_backend.ContainerBackend, imageRef string) (*cdx.BOM, error) {
	// Read /var/lib/pm/index.json from the built image
	indexData, err := containerBackend.ReadFileFromImage(ctx, imageRef, ContainerFactoryIndexPath, container_backend.ReadFileFromImageOpts{})
	if err != nil {
		return nil, fmt.Errorf("read %s from image %q: %w", ContainerFactoryIndexPath, imageRef, err)
	}
	if len(indexData) == 0 {
		return nil, nil
	}

	pkgs, err := ParsePmInstalledJSON(indexData)
	if err != nil {
		return nil, fmt.Errorf("parse pm installed JSON from image %q: %w", imageRef, err)
	}
	if len(pkgs) == 0 {
		return nil, nil
	}

	version := ""
	if v, err := ReadContainerFactoryVersion(ctx, containerBackend, imageRef); err == nil {
		version = v
	}

	return ConvertToCycloneDX(pkgs, version), nil
}
