package os_pm

import (
	"context"
	"fmt"
	"strings"

	"github.com/werf/werf/v2/pkg/config"
	"github.com/werf/werf/v2/pkg/container_backend"
)

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
