package scanner

import (
	"context"
	"fmt"
	"os"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/werf/werf/v2/pkg/sbom"
)

func PrepareWorkingTreeForBOM(ctx context.Context, bom *cdx.BOM, scanOpts ScanOptions) (*WorkingTree, error) {
	wt := NewWorkingTree()

	billNames := BillNamesFromCommands(scanOpts.Commands)

	if err := wt.Create(ctx, os.TempDir(), billNames); err != nil {
		return nil, fmt.Errorf("create working tree: %w", err)
	}

	bomJSON, err := sbom.ToJSON(bom)
	if err != nil {
		wt.Cleanup(ctx)
		return nil, fmt.Errorf("serialize BOM: %w", err)
	}

	if err := wt.WriteBOMToFirstFile(bomJSON); err != nil {
		wt.Cleanup(ctx)
		return nil, fmt.Errorf("write BOM to file: %w", err)
	}

	return wt, nil
}
