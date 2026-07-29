---
title: SBOM Cache Invalidation
type: concept
sources: [S010]
updated: 2026-07-29
---

The SBOM enable state (`build.sbom.enable`) is conditionally included in the stage digest calculation to invalidate the build cache when SBOM generation is toggled on or off (S010).

## Mechanism

A stage digest is a hash computed per build stage that determines whether a cached stage can be reused. When `build.sbom.enable=true`, the digest includes an SBOM enable marker. When `build.sbom.enable=false` (the default), no SBOM marker is included, preserving backward compatibility with existing caches (S010).

- **SBOM disabled → enabled**: the stage digest changes, invalidating all cached stages. All stages are rebuilt with SBOM generation enabled (S010).
- **SBOM disabled → disabled (no change)**: the stage digest is unchanged, cached stages are reused, no SBOM artifacts are generated (S010).
- **SBOM enabled → enabled (no change)**: the stage digest is unchanged, cached stages are reused, SBOM artifacts from the cached build are preserved (S010).

## Cache-affecting vs non-cache-affecting configuration

Only `build.sbom.enable` affects the stage digest. Other SBOM configuration options do NOT affect cache:

- **GOST configuration changes** (`build.sbom.gost`): do NOT change the stage digest. Cached stages are reused, but SBOM artifacts are regenerated during the converge step with the new GOST requirements (S010).
- **Standard selection changes**: do NOT change the stage digest.
- **Per-image SBOM overrides**: only the effective enable state for each image affects that image's stage digest (S010).

## Backward compatibility

When `build.sbom.enable=false` (the default), no SBOM marker is included in the stage digest. This ensures that existing cached stages (built before this feature was introduced or with SBOM disabled) remain valid and are reused (S010).