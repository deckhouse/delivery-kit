package config

import (
	sbomPkg "github.com/werf/werf/v2/pkg/sbom"
)

// buildImageSbom builds image-level SBOM configuration based on meta build settings.
func buildImageSbom(meta *Meta, raw *rawSbom, d *doc) (*Sbom, error) {
	if d == nil {
		// Fallback: avoid panics in error formatting in unexpected edge cases.
		d = &doc{Content: []byte{}}
	}

	if meta == nil {
		return nil, newDetailedConfigError("internal error: meta is not set while building image sbom", nil, d)
	}

	metaSbom := meta.Build.Sbom
	metaEnabled := metaSbom != nil && metaSbom.Enable

	if !metaEnabled {
		if raw != nil {
			return nil, newDetailedConfigError("`sbom` is specified for the image, but `build.sbom.enable` is false", nil, d)
		}
		return nil, nil
	}

	// Determine GOST config (fallback meta -> image).
	gostConfig := metaSbom.Gost
	if raw != nil && raw.Gost != nil {
		gostConfig = gostConfig.Merge(raw.Gost.toConfig())
	}

	return &Sbom{
		Standard: sbomPkg.StandardTypeCycloneDX16,
		Gost:     gostConfig,
	}, nil
}
