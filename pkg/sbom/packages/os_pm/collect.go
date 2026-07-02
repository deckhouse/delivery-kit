package os_pm

import (
	"context"
	"fmt"
	"strings"

	cdx "github.com/CycloneDX/cyclonedx-go"

	"github.com/werf/werf/v2/pkg/container_backend"
)

const packagesVersionEnvName = "PACKAGES_VERSION"

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
	stdout, err := containerBackend.RunCommandInImage(ctx, imageRef, []string{"pm", "info", "--installed", "--json"}, container_backend.RunCommandInImageOpts{})
	if err != nil {
		return nil, fmt.Errorf("run pm info in image %q: %w", imageRef, err)
	}

	pkgs, err := ParsePmInstalledJSON(stdout)
	if err != nil {
		return nil, fmt.Errorf("parse pm info from image %q: %w", imageRef, err)
	}

	return pkgs, nil
}

func readContainerFactoryVersion(ctx context.Context, containerBackend container_backend.ContainerBackend, imageRef string) (string, error) {
	info, err := containerBackend.GetImageInfo(ctx, imageRef, container_backend.GetImageInfoOpts{})
	if err != nil {
		return "", fmt.Errorf("get image info for %q: %w", imageRef, err)
	}
	if info == nil {
		return "", fmt.Errorf("image %q not found", imageRef)
	}

	prefix := packagesVersionEnvName + "="
	for _, env := range info.Env {
		value, ok := strings.CutPrefix(env, prefix)
		if !ok {
			continue
		}

		value = strings.TrimSpace(value)
		if value == "" {
			return "", fmt.Errorf("%s is empty in image %q", packagesVersionEnvName, imageRef)
		}

		return value, nil
	}

	return "", fmt.Errorf("%s not found in image %q config", packagesVersionEnvName, imageRef)
}
