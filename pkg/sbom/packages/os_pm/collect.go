package os_pm

import (
	"bytes"
	"context"
	"fmt"
	"strings"

	cdx "github.com/CycloneDX/cyclonedx-go"

	"github.com/werf/werf/v2/pkg/config"
	"github.com/werf/werf/v2/pkg/docker"
)

func CollectBOM(ctx context.Context, imageRef string) (*cdx.BOM, error) {
	if imageRef == "" {
		return nil, nil
	}

	pkgs, err := collectInstalledPackets(ctx, imageRef)
	if err != nil {
		return nil, err
	}
	if len(pkgs) == 0 {
		return nil, nil
	}

	version, err := readContainerFactoryVersion(ctx, imageRef)
	if err != nil {
		return nil, err
	}

	return ConvertToCycloneDX(pkgs, version), nil
}

func collectInstalledPackets(ctx context.Context, imageRef string) (map[string]PmPackageInfo, error) {
	var stdout, stderr bytes.Buffer
	err := docker.CliRun_ProvidedOutput(ctx, &stdout, &stderr, "--rm", "--entrypoint", "", imageRef, "pm", "info", "--installed", "--json")
	if err != nil {
		return nil, fmt.Errorf("run pm info in image %q: %w (stderr: %s)", imageRef, err, strings.TrimSpace(stderr.String()))
	}

	pkgs, err := ParsePmInstalledJSON(stdout.Bytes())
	if err != nil {
		return nil, fmt.Errorf("parse pm info from image %q: %w", imageRef, err)
	}

	return pkgs, nil
}

func readContainerFactoryVersion(ctx context.Context, imageRef string) (string, error) {
	var stdout, stderr bytes.Buffer
	err := docker.CliRun_ProvidedOutput(ctx, &stdout, &stderr, "--rm", "--entrypoint", "", imageRef, "cat", config.ContainerFactoryVersionFile)
	if err != nil {
		return "", fmt.Errorf("read %s from image %q: %w (stderr: %s)",
			config.ContainerFactoryVersionFile, imageRef, err, strings.TrimSpace(stderr.String()))
	}

	version := strings.TrimSpace(stdout.String())
	if version == "" {
		return "", fmt.Errorf("%s is empty in image %q", config.ContainerFactoryVersionFile, imageRef)
	}

	return version, nil
}
