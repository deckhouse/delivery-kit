package os_pm

import (
	"bytes"
	"context"
	"fmt"
	"strings"

	cdx "github.com/CycloneDX/cyclonedx-go"

	werfExec "github.com/werf/werf/v2/pkg/werf/exec"
)

// CollectBOM runs pm inside the built image to read the installed binary
// packages and converts them to a CycloneDX BOM. It returns nil when imageRef
// is empty.
func CollectBOM(ctx context.Context, imageRef string) (*cdx.BOM, error) {
	if imageRef == "" {
		return nil, nil
	}

	cmd := werfExec.CommandContextCancellation(ctx, "docker", "run", "--rm", "--entrypoint", "", imageRef, "pm", "info", "--installed", "--json")

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		werfExec.TerminateIfCanceled(ctx)
		return nil, fmt.Errorf("run pm info in image %q: %w (stderr: %s)", imageRef, err, strings.TrimSpace(stderr.String()))
	}

	pkgs, err := ParsePmInstalledJSON(stdout.Bytes())
	if err != nil {
		return nil, fmt.Errorf("parse pm info from image %q: %w", imageRef, err)
	}

	return ConvertToCycloneDX(pkgs), nil
}
