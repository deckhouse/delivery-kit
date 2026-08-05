# Tasks: Fallback Index Annotation Loss

## Phase 1: Setup — Create isolated test fixture

- [x] T001 [US1] Create dedicated `werf.yaml` at `test/e2e/sbom/_fixtures/regressions/manifest_annotation/werf.yaml` with unique project name `werf-test-e2e-sbom-annotation-regression`, two images (`frontend`, `backend`), SBOM enabled (cyclonedx@1.6), and `jq==1.8.1` packages only — no overlap with `lifecycle/multi_image`
- [x] T002 [US1] Create dedicated `Dockerfile.builder-base` at `test/e2e/sbom/_fixtures/regressions/manifest_annotation/Dockerfile.builder-base` — content must be structurally independent from `lifecycle/multi_image/Dockerfile.builder-base` to avoid registry tag collisions
- [x] T003 [US1] Create dedicated `werf-giterminism.yaml` at `test/e2e/sbom/_fixtures/regressions/manifest_annotation/werf-giterminism.yaml` allowing `BUILDER_BASE_IMAGE` env var
- [x] T004 Verify fixture isolation: confirm no files or directories are shared between `test/e2e/sbom/_fixtures/regressions/manifest_annotation/` and `test/e2e/sbom/_fixtures/lifecycle/multi_image/`

## Phase 2: Implementation — Regression test for annotation preservation

- [x] T005 [US1] Implement `DescribeTable("manifest annotation preservation: fallback index descriptors carry image-name annotation", ...)` in `test/e2e/sbom/regressions_test.go` using the isolated fixture from Phase 1
- [x] T006 [US1] Build both images (`frontend`, `backend`) and verify they share the same parent digest (enabling fallback index usage)
- [x] T007 [US1] Pull the fallback index tag directly via `go-containerregistry` (`remote.Index`) and verify `io.werf.image-name` annotations are present for both `frontend` and `backend` entries
- [x] T008 [US1] Use `DescribeTable` with entries for `vanilla-docker` and `buildkit-docker` container backends

## Phase 3: Validation — Verify no CI interference

- [x] T009 [US1] Run regression test standalone and confirm pass
- [x] T010 [US1] Run `lifecycle/multi_image` tests standalone and confirm pass
- [x] T011 [US1] Run both suites concurrently and confirm no false-positive failures from fixture overlap

## Dependencies

- Phase 1 (isolated fixture) → Phase 2 (regression test code) → Phase 3 (validation)
- T001–T004 must complete before T005–T008
- T001–T008 must complete before T009–T011

## Parallel execution opportunities

- T001, T002, T003 are parallelizable (different files, no cross-dependencies)

## Implementation strategy

This is a single-user-story feature (US1). MVP scope includes T001–T008: create the isolated fixture and implement the regression test. T009–T011 are validation tasks to be run on CI.

