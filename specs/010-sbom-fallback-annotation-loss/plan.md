# Implementation Plan: Fallback Index Annotation Loss

## Technical Context

The SBOM artifact storage for multi-image builds uses a fallback index mechanism in `pkg/oci/artifact/fallback.go`. When multiple images share the same parent digest, their SBOM artifacts are stored in a shared OCI Image Index tag. The index entries are distinguished by the `io.werf.image-name` annotation on each descriptor.

### How the Fallback Index Works

1. **Push (Attach)**: `Attach()` in `fallback.go` reads the current fallback index, calls `updateFallbackIndex()` to add/replace the entry for the given image name, writes the updated index back, and verifies the write via CAS (compare-and-swap) digest comparison with retries.

2. **Lookup (GetAttached)**: `GetAttached()` in `fallback.go` pulls the fallback index, filters manifests by `artifactType` and `imageName` annotation, and returns the matching descriptor.

3. **Entry replacement**: `updateFallbackIndex()` in `fallback.go` iterates over existing manifests and skips (replaces) entries where the `artifactType` and `io.werf.image-name` annotation match the new entry.

### The Problem

The Docker Distribution registry does not reliably preserve the `annotations` field on descriptors within OCI Image Index manifests across write/read cycles. This causes:

- `updateFallbackIndex()` cannot match existing entries (annotation is empty), so entries accumulate instead of being replaced.
- `GetAttached()` cannot find the entry for the requested image name (annotation is missing), causing "artifact not found" errors.

### The Approach

1. **Regression test**: A Ginkgo test in `test/e2e/sbom/regressions_test.go` that builds two images sharing the same digest, pulls the fallback index directly via `go-containerregistry`, and asserts that `io.werf.image-name` annotations are present for both entries.

2. **Fixture isolation**: The regression test uses a dedicated fixture at `test/e2e/sbom/_fixtures/regressions/manifest_annotation/` that is structurally independent from the `lifecycle/multi_image` fixture. This prevents CI interference — concurrent test execution would otherwise cause fallback index tag collisions and false-positive failures on either side. The fixture must have:
   - A unique project name in `werf.yaml`
   - Its own `Dockerfile.builder-base` (not shared with `lifecycle/multi_image`)
   - Its own `werf-giterminism.yaml`
   - No shared directories or files with `lifecycle/multi_image`

## Project Structure

```
pkg/oci/artifact/
  fallback.go           # Core fallback index logic (push/pull/lookup/update)
  fallback_internal_test.go  # Unit tests for updateFallbackIndex and staticIndex
  store.go              # OCIStore — manages artifact attach/detach

test/e2e/sbom/
  regressions_test.go   # Regression test for annotation preservation (NEW)
  _fixtures/regressions/manifest_annotation/  # Dedicated fixture, isolated from lifecycle/multi_image (NEW)
  _fixtures/regressions/  # Regression test fixtures — independent from lifecycle/ fixtures
```

## Complexity Assessment

| Factor | Assessment |
|--------|------------|
| Files changed | 3 new files (regression test, fixture files: werf.yaml, Dockerfile.builder-base, werf-giterminism.yaml) |
| Source lines | ~100 lines in regression test + fixture |
| Dependencies | OCI registry interaction via `go-containerregistry` |
| Risk | Low — adds a regression test, no production code changes |
| Parallelism | Fixture is isolated from `lifecycle/multi_image` to avoid CI interference when both suites run concurrently |