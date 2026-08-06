# Tasks: Per-Platform SBOM for Multi-Platform Images

**Input**: Design documents from `/specs/016-sbom-multiplatform-per-platform/`

**Prerequisites**: spec.md, plan.md

**Status**: migrated — all tasks reflect work already implemented on `feat/sbom/per-platform-sbom` (commits a0ce84ae1..ab4426ed7)

## Phase 1: Core generation

**Purpose**: Generate one honest SBOM per platform

- [x] T001 [FR-003][FR-004] Include target platform in `calculateStableChecksum` (only when non-empty — golden hashes for the empty platform unchanged) and pass `PullOpts{TargetPlatform}` at the scan pull in `pkg/build/sbom_step.go` (commit a0ce84ae1)
- [x] T002 [FR-003][SC-002] Extend `pkg/build/sbom_step_checksum_test.go`: golden entries keep their hashes with empty platform; platform presence and platform value change the checksum; same platform is stable
- [x] T003 [FR-001][FR-002][FR-009] Rewrite `convergeImageSbom` as a loop over platform images calling `convergePlatformImageSbom`; every input (stage desc, base SBOM, imports, gost config, image context, scan options, platform) comes from the loop image; delete the `MultiplatformImage` index branch (kills latent nil-panic C12a); `purlErrors.Store` → `LoadOrStore` in `pkg/build/build_phase.go` (commit 3fbd7ef27)
- [x] T004 [FR-005] Extract `baseSbomMissingError` with the legacy multi-platform hint appended to the existing label/attach guidance, keeping `%w` wrapping (commit 642b5a7a0)
- [x] T005 [FR-005] Add `pkg/build/sbom_step_error_test.go`: error contains image name, builder label, "rebuild the base image", "legacy platform-ambiguous format", and wraps the cause (`errors.Is`)

## Phase 2: Index platform resolution helpers

**Purpose**: One place that turns (digest, platform) into the right platform manifest digest

- [x] T006 [FR-006][SC-003] Create `pkg/oci/artifact/platform.go`: `ResolvePlatformDigest`, `ListIndexPlatforms`, `NormalizePlatform`, `PlatformMatches`, `ErrIndexPlatformRequired` with a formatted `platform → digest` listing (commits 02168d157 + 3e6d6cc6d)
- [x] T007 [FR-006] Validate `--platform` against a single-platform manifest's config platform (`verifyManifestPlatform`/`checkManifestPlatform`); skip when config has no OS (review finding, commit 3e6d6cc6d)
- [x] T008 [FR-006] Restrict variant prefix-matching to `os/arch` requests (bare `linux` no longer matches); normalize platform input centrally (review finding, commit 3e6d6cc6d)
- [x] T009 [SC-003] Network-free unit tests in `pkg/oci/artifact/platform_test.go`: index dispatch via static `IndexManifest`, unknown-platform (attestation) entries skipped, exact/variant/ambiguous/mismatch/bare-OS matching, `errors.Is(ErrIndexPlatformRequired)`, `NormalizePlatform` table, `checkManifestPlatform` table

## Phase 3: CLI

**Purpose**: Explicit multi-platform addressing, no silent defaults

- [x] T010 [FR-007] `cmd/werf/sbom/get`: `--platform` in `--tag` and `--digest` modes via command-level `ResolveTag` → `ResolvePlatformDigest` → `PullSBOM`; `singlePlatformParam` reads the repeatable flag (env defaults included), rejects multi-values (commit 8aef3bd2f)
- [x] T011 [FR-007] Positional mode: replace by-name `lo.Find` with `selectExportedImage` (filter by name, then platform; multiple matches without `--platform` → error listing built platforms)
- [x] T012 [FR-007] Delete dead `pkg/sbom/image.PullSBOMByTag` (single caller moved to command-level resolution)
- [x] T013 [FR-007] Unit tests `cmd/werf/sbom/get/get_test.go`: not-found, single match, multi-platform without flag (error lists platforms), platform selection, platform not built, multi-value rejection
- [x] T014 [FR-008] `cmd/werf/attest/get` and `cmd/werf/attest/verify`: `--platform` flag piped through `ResolvePlatformDigest` (commit cb73eb642)
- [x] T015 [FR-008] `cmd/werf/attest/ls`: expand index via `ListIndexPlatforms`, render PLATFORM column (`-` for non-index), optional `--platform` filter via `PlatformMatches`
- [x] T016 [FR-008] Unit tests `cmd/werf/attest/ls/ls_test.go`: row rendering, platformless dash, distinct platforms produce distinct rows
- [x] T017 [FR-008] Verify `attest sign`, `sbom merge` unaffected (help renders; recorded in evidence); `task doc:gen` produced zero diff (`--platform` pre-registered in generated docs, attest commands hidden)

## Phase 4: Cleanup verification

**Purpose**: Prove per-platform fallback tags are collected without new deletion logic

- [x] T018 [SC-004] Discovery-layer tests `pkg/storage/repo_stages_storage_orphan_test.go`: per-platform tags orphaned when platform manifests are gone, kept while they exist, non-fallback tags ignored (registry stub via embedded `docker_registry.Interface`) (commit 1817430d2)
- [x] T019 [SC-004] Delete-loop entry in `pkg/cleaning/cleanup_test.go` for per-platform tag names
- [x] T020 Deletion-chain audit (recorded in `.omo/evidence/task-8-c12-multiplatform-sbom.log`): index deletion un-protects platform stages → deleted same run → tags orphan; shared platform stages correctly keep their SBOM; `TODO(multiarch)` at `cleanup.go:479` concerns git-history scanning, not deletion — no gap

## Phase 5: e2e

**Purpose**: End-to-end contract for the whole model

- [x] T021 [SC-001] `test/e2e/sbom/multiplatform_test.go` (label `multiplatform`) + fixture `_fixtures/multiplatform/`: two-platform dockerfile build on a buildx-built multi-arch trusted builder base; asserts per-platform artifact on each platform digest fallback tag, in-toto subject == platform digest, truthful `io.werf.target-platform`, `io.werf.image-name`/checksum annotations, distinct subjects across platforms, NO artifact on the index digest, ≥2 × "Use previously generated SBOM from registry" on rebuild (commits f3bedaf8f + ab4426ed7)

## Dependencies

- T001–T005 (core) and T006–T009 (helpers) were independent; T010–T017 (CLI) depended on T006; T021 depended on the core phase.

## Implementation Strategy

Multi-platform became N sequential runs of the single-platform path inside the existing per-image-name parallelism (`parallel.DoTasks`). The single-platform path is now the only path — net code complexity decreased.

## Identified Gaps

- ⚠️ **e2e suite has never been executed** — compiles (verified via golangci-lint) but requires Linux CI with docker buildx + QEMU binfmt (`task test:setup:environment`). It is the only end-to-end evidence for SC-001 and must gate the PR merge.
- ⚠️ The `img`-vs-`images[0]` correctness inside `convergePlatformImageSbom` is guarded only by the (unexecuted) e2e — no unit-level mutation coverage (conveyor is not unit-mockable here).
- ⚠️ The legacy-base error hint (T004) is unconditional: it also appears for genuinely missing single-platform base SBOMs, because the legacy format cannot be detected (no child→parent resolution in registries). Deliberate tradeoff.
- ⚠️ Replaced-but-not-deleted SBOM artifact manifests remain in the repository and MAY reappear in registry referrers API listings after a registry upgrade (property of the pre-existing replace semantics, not introduced here).
- ⚠️ Old index-attached SBOM artifacts of rebuilt images linger until the next `werf cleanup` orphan pass (by design).
- ⚠️ Two accepted breaking changes (legacy bases hard error; index ref without `--platform` errors) have no feature flag — release-notes visibility required.
