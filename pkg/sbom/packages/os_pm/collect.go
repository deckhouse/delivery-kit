package os_pm

import (
	"context"
	"fmt"
	"strings"

	cdx "github.com/CycloneDX/cyclonedx-go"

	"github.com/werf/werf/v2/pkg/config"
	"github.com/werf/werf/v2/pkg/container_backend"
)

func CollectBOM(ctx context.Context, containerBackend container_backend.ContainerBackend, imageRef, lockPath string) (*cdx.BOM, error) {
	if imageRef == "" {
		return nil, nil
	}

	pkgs, err := collectPacketsFromLock(ctx, containerBackend, imageRef, lockPath)
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

func collectPacketsFromLock(ctx context.Context, containerBackend container_backend.ContainerBackend, imageRef, lockPath string) (map[string]PmPackageInfo, error) {
	stdout, err := containerBackend.RunCommandInImage(ctx, imageRef, []string{"cat", lockPath}, container_backend.RunCommandInImageOpts{})
	if err != nil {
		return nil, fmt.Errorf("read pm lock %s from image %q: %w", lockPath, imageRef, err)
	}

	pkgs, err := ParsePmLockJSON(stdout)
	if err != nil {
		return nil, fmt.Errorf("parse pm lock from image %q: %w", imageRef, err)
	}

	return pkgs, nil
}

func readContainerFactoryVersion(ctx context.Context, containerBackend container_backend.ContainerBackend, imageRef string) (string, error) {
	stdout, err := containerBackend.RunCommandInImage(ctx, imageRef, []string{"cat", config.ContainerFactoryVersionFile}, container_backend.RunCommandInImageOpts{})
	if err != nil {
		return "", fmt.Errorf("read %s from image %q: %w", config.ContainerFactoryVersionFile, imageRef, err)
	}

	version := strings.TrimSpace(string(stdout))
	if version == "" {
		return "", fmt.Errorf("%s is empty in image %q", config.ContainerFactoryVersionFile, imageRef)
	}

	return version, nil
}
