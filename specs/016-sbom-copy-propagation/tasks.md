# Tasks: SBOM Copy Propagation

All tasks completed — reverse-engineered from the implemented feature (branch `feat/sbom/copy-to-final-repo`).

## Phase 1: Copy primitive

- [x] T001 Add `CopyAttachedArtifacts` in `pkg/oci/artifact/copy.go`: pull source fallback index, re-attach each artifact-typed entry onto the destination digest via `OCIStore.Attach`
- [x] T002 Skip entries already attached to the destination with the same identity (`hasEquivalentArtifact`: artifact type + image name + checksum + platform annotations)
- [x] T003 Skip entries without an artifact type (go-containerregistry's own subject descriptors); treat a missing source index as a no-op
- [x] T004 Resolve registry credentials per host for source and destination separately when no explicit remote options are given
- [x] T005 Integration specs in `pkg/oci/artifact/copy_test.go`: same-digest copy, different-digest copy, idempotency, multiple images on one parent, empty source no-op

## Phase 2: Copy-time hooks

- [x] T006 `RepoStagesStorage.CopyFromStorage`: copy attached artifacts after the registry-level stage copy (`pkg/storage/repo_stages_storage.go`)
- [x] T007 `StorageManager.CopySuitableStageDescByDigest`: copy attached artifacts from the secondary source digest onto the destination digest after `StoreImage`, guarded against local storages (`pkg/storage/manager/storage_manager.go`)

## Phase 3: Post-converge catch-up

- [x] T008 Add `sbomStep.PropagateArtifacts` in `pkg/build/sbom_step.go`: copy artifacts into the final repo (fatal on failure) and each cache repo (warning on failure), skipping local storages and the source repo
- [x] T009 Call `PropagateArtifacts` from `convergeImageSbom` after `ConvergeWithMerge`; add `finalStageDescForImage` resolving the final-repo descriptor for single-platform and multiplatform images (`pkg/build/build_phase.go`)
- [x] T010 Integration specs in `pkg/build/sbom_step_propagate_test.go`: final repo copy, cache repo copy with local/same-repo skips, nil final desc no-op, same-repo skip, unreachable cache repo → warning, unreachable final repo → error (mutation-checked: disabling the final-repo copy fails the specs)

## Phase 4: Cleanup parity

- [x] T011 `cleanupOrphanedArtifacts` in `pkg/cleaning/cleanup.go`: run `deleteOrphanedArtifacts` against the final stages storage in addition to the primary
- [x] T012 `purgeManager.deleteOrphanedArtifacts` in `pkg/cleaning/purge.go`: same final-storage pass for `werf purge`

## Phase 5: End-to-end coverage

- [x] T013 Add `test/e2e/sbom/final_repo_test.go` (labels `e2e, sbom, final-repo`): build with `WERF_FINAL_REPO` set, assert the build report references the final repo, run `werf sbom get --repo <final-repo> --digest <digest>`, assert SBOM components. Requires Linux with Docker; compile-checked on macOS. Named mutation for the first Linux run: removing the `PropagateArtifacts` call in `convergeImageSbom` must fail the suite with "artifact not found"
