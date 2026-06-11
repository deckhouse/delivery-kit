package os_pm

import (
	"bytes"
	"context"
	"fmt"
	"strings"

	cdx "github.com/CycloneDX/cyclonedx-go"

	werfExec "github.com/werf/werf/v2/pkg/werf/exec"
)

type BOMPatcher struct {
	imageRef    string
	hasPackages bool
}

func NewBOMPatcher(imageRef string, hasPackages bool) *BOMPatcher {
	return &BOMPatcher{
		imageRef:    imageRef,
		hasPackages: hasPackages,
	}
}

func (p *BOMPatcher) Apply(ctx context.Context, bom *cdx.BOM) (*cdx.BOM, error) {
	if !p.hasPackages || p.imageRef == "" {
		return bom, nil
	}

	cmd := werfExec.CommandContextCancellation(ctx, "docker", "run", "--rm", "--entrypoint", "", p.imageRef, "pm", "info", "--installed", "--json")

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		werfExec.TerminateIfCanceled(ctx)
		return nil, fmt.Errorf("run pm info in image %q: %w (stderr: %s)", p.imageRef, err, strings.TrimSpace(stderr.String()))
	}

	pkgs, err := ParsePmInstalledJSON(stdout.Bytes())
	if err != nil {
		return nil, fmt.Errorf("parse pm info from image %q: %w", p.imageRef, err)
	}

	pmBOM := ConvertToCycloneDX(pkgs)
	if pmBOM == nil {
		return bom, nil
	}

	if bom.Components == nil {
		bom.Components = pmBOM.Components
	} else {
		*bom.Components = append(*bom.Components, *pmBOM.Components...)
	}

	return bom, nil
}
