---
title: SBOM Cache Invalidation
type: concept
sources: [S010, S020, S022]
updated: 2026-08-26
---

The SBOM enable state (`build.sbom.enable`) is conditionally included in the stage digest calculation to invalidate the build cache when SBOM generation is toggled on or off (S010).

## Mechanism

A stage digest is a hash computed per build stage that determines whether a cached stage can be reused. When `build.sbom.enable=true`, the digest includes an SBOM enable marker. When `build.sbom.enable=false` (the default), no SBOM marker is included, preserving backward compatibility with existing caches (S010).

- **SBOM disabled → enabled**: the stage digest changes, invalidating all cached stages. All stages are rebuilt with SBOM generation enabled (S010).
- **SBOM disabled → disabled (no change)**: the stage digest is unchanged, cached stages are reused, no SBOM artifacts are generated (S010).
- **SBOM enabled → enabled (no change)**: the stage digest is unchanged, cached stages are reused, SBOM artifacts from the cached build are preserved (S010).

## Cache-affecting vs non-cache-affecting configuration

A stage digest and an SBOM artifact checksum are two different keys. The stage digest decides whether a cached *image stage* is reused; the SBOM artifact checksum, stored as an annotation on the attached artifact, decides whether a previously generated *SBOM* is reused for that stage. Together they form the SBOM cache key, so the checksum only has to cover generation inputs that leave no trace in the image.

Only `build.sbom.enable` affects the stage digest. Other SBOM configuration options do NOT affect cache:

- **GOST configuration changes** (`build.sbom.gost`): do NOT change the stage digest. Cached stages are reused, but SBOM artifacts are regenerated during the converge step with the new GOST requirements (S010). This is enforced by the artifact checksum, which carries the effective GOST configuration as dedicated parts.
- **Standard selection changes**: do NOT change the stage digest.
- **Per-image SBOM overrides**: only the effective enable state for each image affects that image's stage digest (S010).

## Inputs covered by the stage digest, not the checksum

Some inputs look like SBOM configuration but already reach the SBOM cache key through the parent stage digest, so they are deliberately absent from the artifact checksum:

- **`packages` directive (os-pm)**: the package list is compiled into the generated install command, which feeds the Packages stage digest; the stage itself appears and disappears with the directive. Any toggle or spec change therefore changes the parent digest.
- **Scratch base (`from: scratch`)**: changing the base image changes every stage digest.
- **Image filesystem content** (installed packages, lock files, pm metadata): described by the stage digest by construction.

## Backward compatibility

When `build.sbom.enable=false` (the default), no SBOM marker is included in the stage digest. This ensures that existing cached stages (built before this feature was introduced or with SBOM disabled) remain valid and are reused (S010).

## Platform-aware checksum

For multi-platform images, the target platform is part of `calculateStableChecksum` so that per-platform SBOMs get distinct checksums (S020). The platform occupies a fixed part slot and is always present — an empty value for single-platform builds — because conditionally omitting parts made distinct inputs collapse onto the same checksum input.