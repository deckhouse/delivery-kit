package os_pm

import (
	"context"
	"fmt"
	"strings"

	cdx "github.com/CycloneDX/cyclonedx-go"

	"github.com/werf/werf/v2/pkg/config"
	"github.com/werf/werf/v2/pkg/container_backend"
)

func CollectBOM(ctx context.Context, containerBackend container_backend.ContainerBackend, imageRef string) (*cdx.BOM, error) {
	if imageRef == "" {
		return nil, nil
	}

	pkgs, err := collectInstalledPackets(ctx, containerBackend, imageRef)
	if err != nil {
		return nil, err
	}
	if len(pkgs) == 0 {
		return nil, nil
	}

	version, err := readContainerFactoryVersion(ctx, containerBackend, imageRef)
	if err != nil {
		return nil, err
	}

	return ConvertToCycloneDX(pkgs, version), nil
}

func collectInstalledPackets(ctx context.Context, containerBackend container_backend.ContainerBackend, imageRef string) (map[string]PmPackageInfo, error) {
	stdout, err := containerBackend.ReadFileFromImage(ctx, imageRef, config.ContainerFactoryVersionIndexFile, container_backend.ReadFileFromImageOpts{})
	if err != nil {
		return nil, fmt.Errorf("read pm index from image %q: %w", imageRef, err)
	}

	pkgs, err := ParsePmInstalledJSON(stdout)
	if err != nil {
		return nil, fmt.Errorf("parse pm index from image %q: %w", imageRef, err)
	}

	return pkgs, nil
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
