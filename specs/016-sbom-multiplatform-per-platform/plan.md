# Implementation Plan: Per-Platform SBOM for Multi-Platform Images

**Branch**: `feat/sbom/per-platform-sbom` | **Date**: 2026-08-06 | **Spec**: `specs/016-sbom-multiplatform-per-platform/spec.md`

**Status**: migrated (reverse-engineered from the implemented branch)

**Comparison**: `storage-model-comparison.md` compares delivery-kit's model with BuildKit and OCI Spec

## Summary

Turn the multi-platform SBOM case into N runs of the already-working single-platform pipeline: each platform image is scanned by its own stage tag, merged with its own base/import SBOMs and attached to the fallback tag of its own platform manifest digest with a truthful in-toto subject and platform annotation. The special multi-platform branch (which scanned the index tag and carried a latent nil-dereference) is deleted. CLI commands gain explicit `--platform` addressing with no silent defaults.

## Technical Context

**Language/Version**: Go 1.24.10

**Primary Dependencies**: `google/go-containerregistry` (registry access, index/manifest parsing), `anchore/syft` (scanner, via container backend), `CycloneDX/cyclonedx-go`, Ginkgo/Gomega, `samber/lo`

**Storage**: OCI registry; cosign-v3-compatible artifact layout per OCI distribution-spec 1.1 referrers tag schema. See [`storage-model-comparison.md`](storage-model-comparison.md) § Figure 1 for the registry layout diagram.

**Testing: Ginkgo/Gomega unit tests co-located with sources; e2e suite `test/e2e/sbom` (label `multiplatform`, Linux + buildx/QEMU only)

**Target Platform**: Linux (amd64/arm64); macOS builds a non-CGO binary (no Buildah), e2e deferred to Linux CI

## OCI Storage Model

See [`storage-model-comparison.md`](storage-model-comparison.md) § Figure 1 for the delivery-kit OCI registry layout diagram and comparison with BuildKit and OCI Spec models.

## Key Decisions

1. **Storage model** — per-platform SBOM on the fallback tag of the platform manifest digest; NO merged index-level SBOM. Forced by cosign compatibility: cosign discovery (tag schema / referrers API) is strictly per-digest and cannot walk child→parent; `cosign verify-attestation --platform` and `cosign sign --recursive` embody the same model.
2. **Generation** — multi = N × single path. `convergeImageSbom` loops over platform images; the branch constructing a throwaway `MultiplatformImage` (whose `GetStageDesc()` was always nil — latent panic C12a) is deleted, killing the bug without a separate fix.
3. **Cache compatibility** — platform is appended to `calculateStableChecksum` only when non-empty, keeping single-platform checksums (and caches) byte-identical. Multi-platform cache isolation comes for free: lookups are per parent digest, and old artifacts live on the index digest's tag.
4. **Legacy bases** — hard error (accepted breaking change, no feature flag): a legacy index-attached base SBOM is platform-ambiguous; a fallback lookup would poison the merge. Detection of the legacy format is impossible (no child→parent resolution in registries), so the hint is unconditional in the missing-base-SBOM error.
5. **CLI semantics** — explicit over implicit: an index reference without `--platform` errors listing `platform → digest` pairs (mirrors cosign's `download sbom` UX); no host-platform default. `--platform` against a single-platform manifest is validated against the config platform (one extra config-blob fetch, only when the flag is set). Platform input is normalized (`platformutil.NormalizeUserParams`) centrally in `ResolvePlatformDigest`; variant matching (`linux/arm` → `linux/arm/v7`) is restricted to `os/arch` requests.
6. **Cleanup** — no new deletion logic. The existing orphan pass (`GetOrphanedArtifactNames` → `DeleteArtifact`) is digest-generic; deleting an index un-protects its platform stages (`ProtectionReasonImageIndexPlatform`), they are deleted in the same run, and their fallback tags orphan naturally. Verified by tests and a written deletion-chain trace.

## Project Structure

```
pkg/build/
  build_phase.go            # convergeImageSbom → per-platform loop; convergePlatformImageSbom
  sbom_step.go              # platform in checksum, PullOpts{TargetPlatform}, baseSbomMissingError
pkg/oci/artifact/
  platform.go               # ResolvePlatformDigest, ListIndexPlatforms, NormalizePlatform,
                            # PlatformMatches, ErrIndexPlatformRequired (new file)
pkg/sbom/image/
  image.go                  # PullSBOMByTag removed (dead after command-level resolution)
cmd/werf/sbom/get/          # --platform in tag/digest/positional modes; selectExportedImage
cmd/werf/attest/{get,verify}/  # --platform flag piped through ResolvePlatformDigest
cmd/werf/attest/ls/         # index expansion, PLATFORM column, collectRows/infosToRows
pkg/cleaning/, pkg/storage/ # verification tests only (no production changes)
test/e2e/sbom/
  multiplatform_test.go     # end-to-end contract (label: multiplatform)
  _fixtures/multiplatform/  # two-platform dockerfile project + buildx trusted builder base
```

## Complexity Assessment

20 files, +919/−70 across 10 commits. Net core complexity *decreased*: the index/multi special case was removed and the single-platform path became the only path. New complexity is concentrated in `pkg/oci/artifact/platform.go` (index resolution + validation, ~200 lines) and CLI plumbing.

## Breaking Changes (accepted)

1. Builds on top of legacy multi-platform bases fail until the base is rebuilt (actionable error).
2. `sbom get --tag/--digest` on a multi-platform reference errors instead of silently returning the build host's platform SBOM.

Both need release-notes visibility. Stage digests/tags do not move; single-platform users are unaffected.
