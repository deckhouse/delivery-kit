package nativegate

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"fox.flant.com/deckhouse/container-base/pm.git/sbom/sources"
)

type ReadPackageSourcesOptions struct {
	Binary string
	SHA256 string
}

func ReadPackageSources(ctx context.Context, root string, opts ReadPackageSourcesOptions) (*sources.Receipt, error) {
	if !filepath.IsAbs(root) || !filepath.IsAbs(opts.Binary) {
		return nil, fmt.Errorf("pm sources require absolute root and binary paths")
	}
	if !digestPattern.MatchString("sha256:" + opts.SHA256) {
		return nil, fmt.Errorf("pm sources require a pinned SHA256")
	}
	body, err := os.ReadFile(opts.Binary)
	if err != nil {
		return nil, fmt.Errorf("read pm executable: %w", err)
	}
	if digest(body) != "sha256:"+opts.SHA256 {
		return nil, fmt.Errorf("pm executable SHA256 mismatch: %s", opts.Binary)
	}
	command := exec.CommandContext(ctx, opts.Binary, "sbom-sources", "--root", root)
	var stderr bytes.Buffer
	command.Stderr = &stderr
	data, err := command.Output()
	if err != nil {
		return nil, fmt.Errorf("read pm sources: %w: %s", err, strings.TrimSpace(stderr.String()))
	}
	receipt, status, err := sources.Parse(data)
	if err != nil || status != "present" || receipt == nil {
		return nil, fmt.Errorf("decode pm sources (%s): %w", status, err)
	}
	return receipt, nil
}
