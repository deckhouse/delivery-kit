## Why

When `build.sbom.enable` is toggled from `false` to `true`, werf reuses previously cached build stages from the Container Registry. Since the stage digest does not account for the SBOM enable state, cached stages are reused without SBOM generation, and the converge step (`convergeSbomByImagesSets`) never executes for those images. This results in published images without SBOM artifacts even though SBOM was explicitly enabled.

## What Changes

- When `build.sbom.enable=true`, add an SBOM marker to the stage cache digest so that toggling SBOM on invalidates the stage cache and triggers SBOM generation for rebuilt images.
- When `build.sbom.enable=false` (default), the stage digest MUST remain unchanged — no extra digest inputs are added, preserving backward compatibility with existing cache.
- The scope is limited to `build.sbom.enable` (boolean). Other SBOM-related configuration (`gost`, `standard`, per-image overrides) are out of scope — they affect the SBOM artifact checksum (`sbomStep.calculateStableChecksum`) and are already handled correctly by the SBOM converge path.

## Capabilities

### New Capabilities
- `sbom-cache-invalidation`: When `build.sbom.enable=true`, the stage digest must include an SBOM marker, ensuring stages cached without SBOM are not reused. When `build.sbom.enable=false` (default), digest behavior is unchanged — existing cache remains valid.

### Modified Capabilities

<!-- No existing spec requirements are changing. This is a new build-system-level change. -->

## Impact

- **`pkg/image/const.go`**: `BuildCacheVersion` constant — may need to be bumped or made dynamic.
- **`pkg/build/build_phase.go`**: `calculateDigest` function — needs to include SBOM enable state in the checksum calculation.
- **Build cache**: Existing cached stages built with `build.sbom.enable=false` remain valid for subsequent builds with `enable=false`. When the user switches to `build.sbom.enable=true`, the digest changes due to the added SBOM marker, causing a rebuild of those stages with SBOM generation.