# Implementation Plan: SBOM Copy Propagation

## Technical Context

Go 1.24, go-containerregistry v0.20.1 (`remote`, `registry` fake for tests), Ginkgo v2 + Gomega. New code lives in `pkg/oci/artifact/copy.go`; integration points are `pkg/storage/repo_stages_storage.go`, `pkg/storage/manager/storage_manager.go`, `pkg/build/sbom_step.go`, `pkg/build/build_phase.go`, `pkg/cleaning/cleanup.go`, `pkg/cleaning/purge.go`. Reuses the artifact storage primitives from `specs/014-sbom-artifact-storage-model`: `pullFallbackIndex`, `OCIStore.Attach` (tag lock + convergent index write), werf identity annotations.

### The Problem

SBOMs were attached only in the stages repo. Three stage-copy flows left artifacts behind:

1. **Final repo** (`CopyStageIntoFinalStorage` → `RepoStagesStorage.CopyFromStorage`) — registry-level copy, digest preserved. Runs *before* SBOM generation within a build (`publishFinalImage` at `AfterImages` precedes `convergeSbomByImagesSets`), so even a copy that carried artifacts would miss a freshly generated SBOM.
2. **Cache repos** (`CopyStageIntoCacheStorages`, refill in `FetchStage`) — same registry-level copy, same timing gap.
3. **Secondary → primary** (`CopySuitableStageDescByDigest`) — backend-mediated fetch/rename/store; the destination manifest digest may differ from the source.

Additionally, `werf cleanup`/`werf purge` deleted final-repo stages but their orphaned-artifact pass only covered the primary storage, which would leave `sha256-*` indexes in the final repo orphaned forever once artifacts started landing there.

### The Approach

One primitive, three hooks, one catch-up step, cleanup parity.

1. **`CopyAttachedArtifacts`** (`pkg/oci/artifact/copy.go`): pull the source fallback index; for each artifact-typed entry not already present in the destination with the same identity (artifact type, image name, checksum, platform), pull the payload and re-attach it via `OCIStore.Attach` onto the destination digest. Re-attaching from payload — instead of copying manifests verbatim — makes the primitive digest-agnostic: the subject is always rebuilt against the destination parent. Idempotency comes from the identity check; concurrency safety comes from `Attach`'s tag lock and convergent index write. Missing source index → no-op. Entries without an artifact type (go-containerregistry's own subject descriptors) are skipped — the annotated entry for the same artifact is the one copied.
2. **Copy-time hooks**: `CopyFromStorage` copies artifacts right after the registry stage copy (fatal on failure); `CopySuitableStageDescByDigest` copies them after storing the stage, mapping the source digest to the (possibly different) destination digest, guarded against local storages.
3. **Post-converge catch-up** (`sbomStep.PropagateArtifacts`, called from `convergeImageSbom`): after SBOM generation, copy the image's artifacts into the final repo (fatal) and every cache repo (warning), because the stage copies happened before the SBOM existed. `finalStageDescForImage` resolves the final-repo descriptor for both single-platform and multiplatform images.
4. **Cleanup parity**: `cleanupOrphanedArtifacts` (cleanup) and `deleteOrphanedArtifacts` (purge) run against the final stages storage in addition to the primary one.

### Failure Semantics

Mirrors the surrounding stage-copy semantics: final repo — fatal, cache repos — warning, stage copy paths — fatal (they already fail the copy on any error).

## Project Structure

| Path | Role |
|------|------|
| `pkg/oci/artifact/copy.go` | `CopyAttachedArtifacts` + identity comparison |
| `pkg/oci/artifact/copy_test.go` | Integration specs against the fake registry |
| `pkg/build/sbom_step.go` | `PropagateArtifacts` post-converge catch-up |
| `pkg/build/sbom_step_propagate_test.go` | Integration specs for the catch-up step |
| `pkg/build/build_phase.go` | Call site + `finalStageDescForImage` |
| `pkg/storage/repo_stages_storage.go` | Copy-time hook (registry copies) |
| `pkg/storage/manager/storage_manager.go` | Copy-time hook (secondary→primary) |
| `pkg/cleaning/cleanup.go`, `pkg/cleaning/purge.go` | Final-repo orphan cleanup |
| `test/e2e/sbom/final_repo_test.go` | End-to-end: build with `--final-repo` → `sbom get` by digest |

## Complexity Assessment

Low-to-moderate: ~130 lines of new logic reusing existing primitives, ~75 lines of call-site changes, ~350 lines of tests. No new dependencies, no schema or CLI changes.
