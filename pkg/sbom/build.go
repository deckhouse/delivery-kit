package sbom

import (
	"fmt"
	"os"
	"path/filepath"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/werf/common-go/pkg/util"
)

const (
	SbomDockerfile = "FROM scratch\nCOPY ./sbom /sbom\n"
	SbomDir        = "sbom"
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

// bomFileName returns the file name in format: cyclonedx@1.6/<checksum>.json
// This matches the structure created by scanner.WorkingTree
func bomFileName() string {
	// These values match DefaultSyftScanOptions() in scanner package
	// Note: TypeSyft.String() returns "Syft", SourceTypeDocker.String() returns "docker"
	checksum := util.Sha256Hash(
		"scanner_type", "Syft",
		"source_type", "docker",
		"output_standard", StandardTypeCycloneDX16.String(),
	)
	return filepath.Join(StandardTypeCycloneDX16.String(), fmt.Sprintf("%s.json", checksum))
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

	bomFile := bomFileName()

	bc := &BuildContext{
		Dir:        tmpDir,
		Dockerfile: SbomDockerfile,
		Files:      []string{filepath.Join(SbomDir, bomFile), "Dockerfile"},
	}

	// Create directory structure: sbom/cyclonedx@1.6/
	bomFileDir := filepath.Join(tmpDir, SbomDir, filepath.Dir(bomFile))
	if err := os.MkdirAll(bomFileDir, 0o755); err != nil {
		bc.Cleanup()
		return nil, fmt.Errorf("unable to create sbom dir structure: %w", err)
	}

	// Write bom file: sbom/cyclonedx@1.6/<checksum>.json
	if err := os.WriteFile(filepath.Join(tmpDir, SbomDir, bomFile), bomJSON, 0o644); err != nil {
		bc.Cleanup()
		return nil, fmt.Errorf("unable to write bom file: %w", err)
	}

	if err := os.WriteFile(filepath.Join(tmpDir, "Dockerfile"), []byte(SbomDockerfile), 0o644); err != nil {
		bc.Cleanup()
		return nil, fmt.Errorf("unable to write Dockerfile: %w", err)
	}

	return bc, nil
}
