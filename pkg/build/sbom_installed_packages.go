package build

import (
	"context"
	"fmt"

	cdx "github.com/CycloneDX/cyclonedx-go"

	"github.com/werf/werf/v3/pkg/image"
	"github.com/werf/werf/v3/pkg/sbom/managedinput"
	"github.com/werf/werf/v3/pkg/sbom/scanner"
	"github.com/werf/werf/v3/pkg/sbom/shippedscope"
)

func (step *sbomStep) scanInstalledPackages(ctx context.Context, imageInfo *image.Info, scanOpts scanner.ScanOptions, index *shippedscope.FileIndex, targetPlatform string) ([]*cdx.BOM, error) {
	files := shippedscope.InstalledPackageFiles(ctx, index)
	catalogers := []struct {
		ecosystem shippedscope.Ecosystem
		name      string
		language  string
	}{
		{shippedscope.EcosystemPython, "python-installed-package-cataloger", "Python"},
		{shippedscope.EcosystemJavaScript, "javascript-package-cataloger", "JavaScript"},
		{shippedscope.EcosystemLua, "lua-rock-cataloger", "Lua"},
	}

	var boms []*cdx.BOM
	for _, entry := range catalogers {
		paths := files[entry.ecosystem]
		if len(paths) == 0 {
			continue
		}
		cataloger := scanner.Cataloger{Name: entry.name, SourceLang: entry.language}
		dir, cleanup, err := managedinput.MaterializeInstalledFiles(ctx, step.containerBackend, imageInfo.Name, paths, targetPlatform)
		if err != nil {
			return nil, fmt.Errorf("materialize installed package metadata for %q: %w", entry.name, err)
		}
		bom, _, err := step.scanCatalogerDir(ctx, scanOpts, cataloger, dir, imageInfo.Name, targetPlatform)
		cleanup(ctx)
		if err != nil {
			return nil, err
		}

		// Installed metadata does not identify which extras or runtime environment a
		// project selected. Keep dependency attribution in the declaration/lock scans.
		bom.Dependencies = nil
		boms = append(boms, bom)
	}

	return boms, nil
}
