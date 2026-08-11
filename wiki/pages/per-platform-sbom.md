---
title: Per-Platform SBOM for Multi-Platform Images
type: decision
sources: [S020, S021]
updated: 2026-08-11
---

## Problem

For a multi-platform image (e.g. `linux/amd64` + `linux/arm64`), one SBOM was generated per image *name*, but it was platform-ambiguous on every axis: syft scanned the index tag (pull resolved to the build host's platform, so the other platform's packages were absent), the `io.werf.target-platform` annotation claimed only the first platform in the list, the base image SBOM was merged from the first platform only, and the in-toto `subject` pointed at the index digest instead of a platform manifest digest (S020).

## Chosen approach: per-platform SBOMs

Each platform manifest gets its own honest SBOM artifact (S020). The delivery-kit storage model (fallback tags, DSSE envelopes, no index-level artifacts) is compared with BuildKit and OCI Spec approaches in the [storage model comparison](./storage-model-comparison.md) (S021).

- **Generation**: `convergeImageSbom` loops over platform images, calling `convergePlatformImageSbom` for each. The old `MultiplatformImage` branch (which scanned the index tag and had a latent nil-dereference) was deleted (S020).
- **Storage**: per-platform SBOMs live on the fallback tag of that platform's own manifest digest. No SBOM artifact is attached to the index digest (S020).
- **Subject**: the in-toto statement subject equals that platform's manifest digest, not the index digest (S020).
- **Checksum**: the target platform is included in `calculateStableChecksum` only when non-empty, keeping single-platform checksums (and caches) byte-identical (S020).
- **Base/import SBOMs**: each platform merges its own base image and import SBOMs (S020).
- **Annotation**: `io.werf.target-platform` is set to the platform that was actually scanned (S020).

## Alternatives rejected

- **Merged index-level SBOM**: decided against. Can be added later without migration, but cosign compatibility (which is per-digest) forces the per-platform model (S020).
- **Fallback lookup of legacy index-attached base SBOMs**: rejected — would merge platform-ambiguous data. A legacy base SBOM produces a hard error telling the user to rebuild the base with a newer version (S020).

## CLI consequences

All multi-platform SBOM and attestation CLI commands gained explicit `--platform` addressing. An index reference without `--platform` fails with an error listing the available platforms and their digests. No host-platform default exists anywhere (S020).

See also: [Storage model comparison](./storage-model-comparison.md), [Fallback index mechanism](./fallback-index-mechanism.md), [Attestation subsystem](./attestation-subsystem.md), [werf attest commands](./werf-attest-commands.md), [SBOM cache invalidation](./sbom-cache-invalidation.md), [SBOM e2e test strategy](./sbom-e2e-test-strategy.md).