package sbom

import (
	"fmt"
	"os"
	"path/filepath"

	cdx "github.com/CycloneDX/cyclonedx-go"
)

const (
	SbomDockerfile = "FROM scratch\nCOPY ./sbom /sbom\n"
	SbomDir        = "sbom"
	BomFileName    = "bom.json"
)

type BuildContext struct {
	Dir        string
	Dockerfile string
	Files      []string
}

func (bc *BuildContext) Cleanup() {
	if bc.Dir != "" {
		os.RemoveAll(bc.Dir)
	}
}

func PrepareBuildContext(bom *cdx.BOM) (*BuildContext, error) {
	bomJSON, err := ToJSON(bom)
	if err != nil {
		return nil, fmt.Errorf("unable to serialize BOM: %w", err)
	}

	tmpDir, err := os.MkdirTemp("", "sbom-")
	if err != nil {
		return nil, fmt.Errorf("unable to create temp dir: %w", err)
	}

	bc := &BuildContext{
		Dir:        tmpDir,
		Dockerfile: SbomDockerfile,
		Files:      []string{filepath.Join(SbomDir, BomFileName), "Dockerfile"},
	}

	sbomDir := filepath.Join(tmpDir, SbomDir)
	if err := os.Mkdir(sbomDir, 0o755); err != nil {
		bc.Cleanup()
		return nil, fmt.Errorf("unable to create sbom dir: %w", err)
	}

	if err := os.WriteFile(filepath.Join(sbomDir, BomFileName), bomJSON, 0o644); err != nil {
		bc.Cleanup()
		return nil, fmt.Errorf("unable to write bom.json: %w", err)
	}

	if err := os.WriteFile(filepath.Join(tmpDir, "Dockerfile"), []byte(SbomDockerfile), 0o644); err != nil {
		bc.Cleanup()
		return nil, fmt.Errorf("unable to write Dockerfile: %w", err)
	}

	return bc, nil
}
