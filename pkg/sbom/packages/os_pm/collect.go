package os_pm

import (
	"context"
	"fmt"
	"os"
	"strings"

	cdx "github.com/CycloneDX/cyclonedx-go"

	"github.com/werf/werf/v2/pkg/config"
	"github.com/werf/werf/v2/pkg/container_backend"
)

func readContainerFactoryVersionFromEnv() string {
	return os.Getenv("PACKAGES_VERSION")
}

func ReadContainerFactoryVersion(ctx context.Context, containerBackend container_backend.ContainerBackend, imageRef string) (string, error) {
	return readContainerFactoryVersion(ctx, containerBackend, imageRef)
}

func readContainerFactoryVersion(ctx context.Context, containerBackend container_backend.ContainerBackend, imageRef string) (string, error) {
	stdout, err := containerBackend.ReadFileFromImage(ctx, imageRef, config.ContainerFactoryVersionFile, container_backend.ReadFileFromImageOpts{})
	if err != nil {
		return "", fmt.Errorf("read %s from image %q: %w", config.ContainerFactoryVersionFile, imageRef, err)
	}

	version := strings.TrimSpace(string(stdout))
	if version == "" {
		return "", fmt.Errorf("%s is empty in image %q", config.ContainerFactoryVersionFile, imageRef)
	}

	return version, nil
}

func CollectBOM(ctx context.Context, containerBackend container_backend.ContainerBackend, imageRef string) (*cdx.BOM, error) {
	// Read /var/lib/pm/index.json from the built image
	indexData, err := containerBackend.ReadFileFromImage(ctx, imageRef, "/var/lib/pm/index.json", container_backend.ReadFileFromImageOpts{})
	if err != nil {
		return nil, fmt.Errorf("read /var/lib/pm/index.json from image %q: %w", imageRef, err)
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

	// Resolve containerFactoryVersion: env first, then image file
	version := readContainerFactoryVersionFromEnv()
	if version == "" {
		if v, err := ReadContainerFactoryVersion(ctx, containerBackend, imageRef); err == nil {
			version = v
		}
	}

	return ConvertToCycloneDX(pkgs, version), nil
}
