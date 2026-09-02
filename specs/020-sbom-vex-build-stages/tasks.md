# Tasks: SBOM and VEX as Build Stages

**Input**: Design documents from `specs/020-sbom-vex-build-stages/`

**Prerequisites**: `plan.md`, `spec.md`, `research.md`, `data-model.md`, `quickstart.md`

**Tests**: Included because the feature specification requires independent testing for every user story. New tests must use co-located Ginkgo/Gomega suites and existing e2e fixtures.

## Phase 1: Setup (Shared Infrastructure)

**Purpose**: Establish the implementation baseline without changing user-facing CLI semantics.

- [X] T001 Inventory existing stage, SBOM, VEX, artifact, storage-copy, and cleanup call paths in `pkg/build/`, `pkg/build/stage/`, `pkg/oci/artifact/`, `pkg/storage/`, `pkg/storage/manager/`, and `pkg/cleaning/`, recording the concrete integration points in `specs/020-sbom-vex-build-stages/`
- [X] T002 [P] Inspect existing SBOM and VEX unit/e2e fixture conventions in `pkg/build/`, `test/e2e/sbom/`, and `test/e2e/vex/` and identify reusable helpers without adding a second test harness
- [X] T003 [P] Confirm the existing fallback-tag artifact index, `StagesStorage` implementations, and cleanup compatibility expectations in `pkg/oci/artifact/`, `pkg/storage/`, and `pkg/cleaning/` before modifying propagation code

---

## Phase 2: Foundational (Blocking Prerequisites)

**Purpose**: Define the minimal internal contracts shared by both artifact stages, including the dedicated artifact lifecycle hook and storage abstraction boundary.

**Checkpoint**: Stage metadata, final-image subject flow, `MutateArtifact` lifecycle hook, checksum contract, storage artifact operations, propagation shape, and early registry validation are understood before story implementation begins.

- [X] T004 Define internal artifact-stage metadata and stage-name constants in `pkg/build/stage/base.go`, including final image descriptor, artifact kind, target platform, mutable flag, and non-buildable flag
- [X] T005 Define the kind-neutral artifact propagation operation and explicit source/destination final-image descriptor flow in `pkg/build/` using existing `pkg/oci/artifact/` primitives, without introducing a public API or new dependency
- [X] T006 Locate the earliest common build initialization path and specify the registry-backed-storage validation seam in `pkg/build/build_phase.go` for both SBOM-enabled and VEX-enabled builds
- [ ] T007 Extend `StorageManager` with minimal artifact listing, publication, destination-descriptor resolution, and copy operations in `pkg/storage/manager/`, routing each operation to the correct primary, secondary, cache, or final `storage.StagesStorage` instance
- [ ] T008 Add the dedicated `MutateArtifact` lifecycle hook and scheduler/conveyor dispatch contract, keeping `MutateImage` reserved for image-manifest mutations, in `pkg/build/stage/`, `pkg/build/conveyor.go`, and `pkg/build/`
- [ ] T009 [P] Define the artifact-stage checksum contract using `GetDependencies`, `GetContentDependencies`, and `util.Sha256Hash(args...)` in `pkg/build/stage/`, following `SignStage`
- [X] T010 [P] Add shared test fixtures or helper functions needed to construct final manifest/index descriptors and fallback artifact indexes in co-located files under `pkg/build/` and `pkg/oci/artifact/`
- [X] T011 [P] Define the minimal OCI-artifact primitives on `storage.StagesStorage` in `pkg/storage/stages_storage.go` for listing attached artifacts, publishing an artifact for a final image digest, and copying attached artifacts between destination descriptors; keep repository selection outside the backend
- [X] T012 [P] Implement the new `StagesStorage` artifact primitives for every registry-backed storage implementation under `pkg/storage/` and keep local-storage behavior explicit and unsupported for artifact publication
- [ ] T013 [P] Add Ginkgo/Gomega contract tests for `StagesStorage` artifact primitives, `StorageManager` repository routing, and `MutateArtifact` dispatch, verifying stage code imports neither concrete registry clients nor repository-selection logic in `pkg/storage/stages_storage_test.go`, `pkg/storage/manager/`, `pkg/build/stage/`, and `pkg/build/`

---

## Phase 3: User Story 1 - Artifacts follow published images (Priority: P1) 🎯 MVP

**Goal**: Replace transitional SBOM/VEX steps with lifecycle-owned OCI-artifact stages and make all attached artifacts follow images into primary, final, cache, and secondary-restored destinations through `StorageManager` routing.

**Independent Test**: Build the existing fixture with primary-only, final, cache, combined final/cache, identical-address, and secondary-repository configurations; retrieve both artifact kinds by each destination image digest.

### Tests for User Story 1

- [X] T014 [US1] Add Ginkgo/Gomega unit coverage for artifact-stage mutability, non-buildability, final-image descriptor association, no filesystem mutation, dedicated `MutateArtifact` dispatch, and stage lifecycle behavior in `pkg/build/stage/artifact_test.go`
- [X] T015 [US1] Add Ginkgo/Gomega unit coverage for shared propagation, destination digest resolution, identical-repository skipping, and artifact identity deduplication in `pkg/build/artifact_propagation_test.go`
- [X] T016 [US1] Add Ginkgo/Gomega unit coverage for secondary-to-primary restoration and missing-source-artifact handling in `pkg/build/artifact_propagation_test.go`
- [ ] T017 [US1] Extend the SBOM e2e suite in `test/e2e/sbom/` for primary-only, final, cache, combined final/cache, identical-address, and secondary-repository artifact availability scenarios
- [X] T018 [US1] Add Ginkgo/Gomega migration coverage proving all SBOM callers use `SbomStage` and all VEX callers use `VexStage`, with no `sbomStep` or `vexStep` references remaining in `pkg/build/`
- [ ] T019 [US1] Add Ginkgo/Gomega tests proving `SbomStage` and `VexStage` route registry reads, writes, copies, metadata, and artifact operations through `StorageManager`, with the manager selecting the appropriate `storage.StagesStorage`, in `pkg/build/stage/` and `pkg/storage/manager/`

### Implementation for User Story 1

- [X] T020 [P] [US1] Implement the registry-only mutable, non-buildable `SbomStage` in `pkg/build/stage/sbom.go`, including final-image-digest association and SBOM generation, cache identity, signing, attestation publication, and fallback-index interaction through `StorageManager`
- [X] T021 [P] [US1] Implement the registry-only mutable, non-buildable `VexStage` in `pkg/build/stage/vex.go`, including final-image-digest association and VEX generation, cache identity, signing, attestation publication, and fallback-index interaction through `StorageManager`
- [ ] T022 [US1] Migrate all SBOM behavior and callers from `sbomStep` into `SbomStage` in `pkg/build/`, preserving existing generation, checksum, signing, publication, and fallback-index behavior while routing repository operations through `StorageManager`
- [ ] T023 [US1] Migrate all VEX behavior and callers from `vexStep` into `VexStage` in `pkg/build/`, preserving existing generation, checksum, signing, publication, and fallback-index behavior while routing repository operations through `StorageManager`
- [ ] T024 [US1] Ensure `PrepareImage` is a no-op, `MutateArtifact` operates only on the associated OCI artifact through `StorageManager`, and the artifact stages do not implement or invoke `MutateImage`; do not fetch, rebuild, store, or mutate image filesystem/layers in `pkg/build/stage/sbom.go` and `pkg/build/stage/vex.go`
- [ ] T025 [US1] Register `SbomStage` and `VexStage` after the content-producing stage for Stapel, Dockerfile, and restored-stage image paths in `pkg/build/build_phase.go`
- [ ] T026 [US1] Execute artifact publication through stage `MutateArtifact` without changing image filesystem or layer content, and remove duplicate SBOM/VEX generation from `BuildPhase.AfterImages` while retaining unrelated publication/report work in `pkg/build/build_phase.go`
- [X] T027 [US1] Delete transitional `pkg/build/sbom_step.go`, `pkg/build/vex_step.go`, and their step-specific tests after all callers and migration tests use `SbomStage` and `VexStage`
- [X] T028 [US1] Implement shared idempotent artifact propagation through `StorageManager`, with manager-routed source/destination backends, destination descriptor resolution, identical-address skipping, fallback-index deduplication, and all-artifact copying in `pkg/build/artifact_propagation.go` and `pkg/storage/manager/`
- [X] T029 [US1] Connect primary-to-final and primary-to-cache image-copy paths to the `StorageManager`-routed propagation operation while preserving fatal final errors and best-effort cache warnings in `pkg/build/` and `pkg/storage/manager/`
- [X] T030 [US1] Connect secondary-stage restoration into primary storage to the same `StorageManager`-routed propagation operation, including explicit handling when a source artifact is absent, in `pkg/storage/manager/` and `pkg/build/`

**Checkpoint**: User Story 1 is independently functional; `SbomStage` and `VexStage` are the sole lifecycle owners, operate on final-image-associated OCI artifacts, and artifacts follow every applicable published image.

---

## Phase 4: User Story 2 - Platform-specific artifacts describe the correct image (Priority: P1)

**Goal**: Attach per-platform SBOMs to final platform manifests and attach exactly one image-level VEX to the correct single-platform manifest or multi-platform index.

**Independent Test**: Build a two-platform fixture, inspect each artifact subject and platform metadata, and verify that multi-platform VEX appears only on the final image index while single-platform VEX uses the final manifest.

### Tests for User Story 2

- [X] T031 [P] [US2] Add Ginkgo/Gomega unit tests for single-platform and multi-platform final-image subject selection in `pkg/build/artifact_subject_test.go`
- [X] T032 [P] [US2] Add Ginkgo/Gomega unit tests proving platform SBOM metadata and final parent digest are distinct per platform in `pkg/build/stage/sbom_test.go`
- [X] T033 [US2] Move or rename platform-subject tests from transitional `pkg/build/sbom_step_test.go` into stage-owned tests and ensure the final suite contains no step-specific test dependency
- [ ] T034 [US2] Extend `test/e2e/sbom/` with two-platform subject and metadata assertions for each final platform manifest
- [X] T035 [US2] Extend `test/e2e/vex/` with single-platform final-manifest placement and multi-platform final-index-only placement assertions
- [ ] T036 [US2] Add storage-backed tests for destination platform/index descriptor resolution when the copied image digest differs from the source in `pkg/build/artifact_propagation_test.go`

### Implementation for User Story 2

- [X] T037 [US2] Implement explicit final-image artifact subject resolution for published manifest and index descriptors in `pkg/build/artifact_subject.go`
- [ ] T038 [US2] Pass the final target platform and resolved final platform manifest descriptor through `SbomStage` creation and publication in `pkg/build/stage/sbom.go` and `pkg/build/build_phase.go`
- [ ] T039 [US2] Make `VexStage` registration run once per multi-platform image set with the final top-level index subject, and use the final image manifest subject for single-platform builds in `pkg/build/stage/vex.go` and `pkg/build/build_phase.go`
- [X] T040 [US2] Ensure `StorageManager`-routed propagation resolves the corresponding destination platform manifest or image index before attaching artifacts, including destinations with differing source digests, in `pkg/build/artifact_propagation.go`, `pkg/storage/manager/`, and `pkg/storage/`

**Checkpoint**: User Story 2 is independently testable and no artifact can silently use an index subject for a platform SBOM or duplicate multi-platform VEX onto platform manifests.

---

## Phase 5: User Story 3 - Rebuilds reuse or invalidate artifact results correctly (Priority: P1)

**Goal**: Preserve valid artifact cache hits while preventing stale reuse when image, scanner, merge/GOST, VEX document, platform, format, or signing inputs change; cache ownership lives in the artifact stages.

**Independent Test**: Repeat unchanged builds and then change each effective artifact input one at a time; inspect cache decisions, artifact identities, and duplicate fallback-index entries.

### Tests for User Story 3

- [X] T041 [P] [US3] Add Ginkgo/Gomega tests for `SbomStage` dependency identity across final image digest, scanner, merge/GOST, format, signer, and target-platform inputs in `pkg/build/stage/sbom_test.go`
- [X] T042 [P] [US3] Add Ginkgo/Gomega tests for `VexStage` dependency identity across final parent digest, document content, format, and signer inputs in `pkg/build/stage/vex_test.go`
- [X] T043 [US3] Add Ginkgo/Gomega tests for repeated idempotent publication and cache-restored artifact processing through `StorageManager` in `pkg/build/artifact_propagation_test.go`
- [ ] T044 [US3] Extend `test/e2e/sbom/` and `test/e2e/vex/` with unchanged rebuild, changed-input, signing-identity, and restored-cache scenarios
- [X] T045 [US3] Remove or migrate any remaining cache-identity assertions from deleted `pkg/build/sbom_step_test.go` and `pkg/build/vex_step_test.go` into stage-owned tests

### Implementation for User Story 3

- [X] T046 [US3] Include all effective SBOM inputs and the final parent image identity in `SbomStage` dependency calculation while preserving existing checksum semantics in `pkg/build/stage/sbom.go`
- [X] T047 [US3] Include VEX document content, final parent descriptor identity, format version, and signer identity in `VexStage` dependency calculation in `pkg/build/stage/vex.go`
- [ ] T048 [US3] Select reusable artifact-bearing stages from primary and secondary storage through `StorageManager` using the complete dependency identity, and apply identical processing to locally built and cache-restored images in `pkg/build/` and `pkg/storage/manager/`
- [X] T049 [US3] Preserve fallback-index convergence and prevent duplicate entries during repeated or concurrent artifact publication in `pkg/oci/artifact/`, `pkg/storage/`, and `pkg/build/artifact_propagation.go`

**Checkpoint**: User Story 3 is independently testable; unchanged inputs reuse artifacts and every effective changed input invalidates only the affected artifact identity.

---

## Phase 6: User Story 4 - Registry failures have predictable consequences (Priority: P2)

**Goal**: Reject unsupported local-only artifact builds early, fail on final-repository artifact errors, and retain distinguishable best-effort behavior for cache errors.

**Independent Test**: Exercise unavailable final and cache repositories, missing secondary artifacts, concurrent attachment, and no-registry builds; verify build result and actionable diagnostics.

### Tests for User Story 4

- [X] T050 [P] [US4] Add Ginkgo/Gomega unit tests proving artifact-enabled local-only builds fail before any image stage executes in `pkg/build/build_phase_test.go`
- [X] T051 [P] [US4] Add Ginkgo/Gomega unit tests for fatal final propagation errors and non-fatal, clearly logged cache propagation errors in `pkg/build/artifact_propagation_test.go`
- [X] T052 [P] [US4] Add Ginkgo/Gomega concurrency tests that retain every fallback-index artifact entry during concurrent `StorageManager`-routed attachment in `pkg/oci/artifact/`, `pkg/storage/manager/`, and `pkg/storage/`
- [ ] T053 [US4] Extend `test/e2e/sbom/` and `test/e2e/vex/` for unavailable final/cache repositories, local-only rejection, and missing secondary source artifact behavior
- [X] T054 [US4] Extend cleanup coverage in `pkg/cleaning/` and relevant e2e fixtures to verify orphan fallback artifact indexes are removed from primary and propagated repositories

### Implementation for User Story 4

- [X] T055 [US4] Add earliest-phase registry-backed-storage validation for enabled SBOM/VEX with an actionable `--repo` or disable-artifacts message in `pkg/build/build_phase.go`
- [X] T056 [US4] Enforce fatal final-repository publication/propagation errors and best-effort cache-repository warnings through one shared `StorageManager`-routed error-policy path in `pkg/build/artifact_propagation.go` and `pkg/storage/manager/`
- [X] T057 [US4] Ensure missing secondary source artifacts return an incomplete/error result rather than claiming artifact-complete restoration in `pkg/build/` and `pkg/storage/manager/`
- [X] T058 [US4] Verify artifact propagation does not bypass existing cleanup and purge behavior, updating only the necessary repository traversal in `pkg/cleaning/`

**Checkpoint**: User Story 4 is independently testable; registry failures and local-only configuration produce predictable results without changing repository flag semantics.

---

## Phase 7: Polish & Cross-Cutting Concerns

**Purpose**: Validate the complete implementation against the revised stage-ownership and storage-abstraction boundaries.

- [X] T059 [P] Review `pkg/build/`, `pkg/build/stage/`, `pkg/storage/`, `pkg/storage/manager/`, `pkg/oci/artifact/`, and `pkg/cleaning/` for unnecessary public surface, direct registry-client access from stages, duplicate convergence paths, unwrapped errors, and comments that do not explain non-obvious logic
- [ ] T060 [P] Verify no `sbomStep` or `vexStep` types, constructors, callers, or compatibility wrappers remain in `pkg/build/`, verify no step-specific tests remain, and verify `SbomStage`/`VexStage` are the sole lifecycle owners
- [ ] T061 [P] Verify all stage registry interaction goes through `StorageManager`, the manager routes to all supported registry-backed `storage.StagesStorage` implementations, and local storage rejects artifact publication explicitly in `pkg/storage/` and `pkg/storage/manager/`
- [ ] T062 [P] Verify existing builds with SBOM/VEX disabled and existing `--repo`, `--final-repo`, `--cache-repo`, and `--secondary-repo` semantics in `test/legacy_e2e/` and relevant unit fixtures
- [X] T063 Run formatting with `task format` for authored Go directories
- [X] T064 Run compilation with `task build`
- [X] T065 Install the lint prerequisite with `task deps:install:golangci-lint` and run repository lint with `task lint`
- [ ] T066 Run the complete unit suite with `task test:unit`
- [X] T067 Run scoped SBOM e2e coverage with `task test:e2e paths="./test/e2e/sbom/..." labelFilter="sbom"`
- [X] T068 Run scoped VEX e2e coverage with `task test:e2e paths="./test/e2e/vex/..." labelFilter="vex"`
- [ ] T069 Run legacy integration coverage with `task test:integration`
- [X] T070 Confirm authored-file whitespace and generated-file scope with `git diff --check` limited to changed authored files, without modifying `CHANGELOG.md` or generated CLI reference files

---

## Dependencies & Execution Order

### Phase Dependencies

- **Phase 1 (Setup)**: No implementation dependency; establishes the current call-path and storage baseline.
- **Phase 2 (Foundational)**: Depends on Phase 1 and blocks story implementation. `MutateArtifact` dispatch, checksum conventions, `StorageManager` routing, `StagesStorage` primitives, and backend implementations must be available before artifact stages can publish or propagate OCI artifacts.
- **Phase 3 (US1)**: Depends on Phase 2 and is the MVP increment. It includes full migration from `sbomStep`/`vexStep`, final-image-digest association, `MutateArtifact` integration, manager-routed storage, and deletion of transitional files.
- **Phase 4 (US2)**: Depends on US1's artifact stages and propagation path because it specializes final subject selection; platform tests must be owned by the new stages before old step tests are deleted.
- **Phase 5 (US3)**: Depends on US1 and US2 stage identity/subject contracts so cache identity includes the correct final parent descriptor.
- **Phase 6 (US4)**: Depends on the shared `StorageManager`-routed propagation operation from US1; its validation work can proceed in parallel with US2/US3 after the shared path exists.
- **Phase 7 (Polish)**: Depends on all desired stories being complete, including removal of transitional files and references and validation of every storage implementation.

### User Story Dependencies

- **US1 (P1)**: Starts after Phase 2; no dependency on another user story. MVP.
- **US2 (P1)**: Depends on US1's `SbomStage`/`VexStage` lifecycle and `StorageManager`-routed propagation implementation.
- **US3 (P1)**: Depends on US1's stages and US2's explicit final-image subject rules.
- **US4 (P2)**: Depends on US1's propagation/error path; early-validation tests can proceed independently of US2 and US3.

### Parallel Opportunities

- Phase 1 tasks T002 and T003 can run in parallel after T001's baseline inventory.
- In Phase 2, T009–T013 can proceed in parallel once the required lifecycle and storage method shapes are agreed; backend implementations must converge on the same interface, while `MutateArtifact` dispatch remains a prerequisite for the stages.
- Within US1, T020 and T021 are parallel stage files; T012, T013, and T019 are separate test concerns. T022 and T023 are parallel migrations when their callers are disjoint.
- Within US2, T031/T032 and T034–T036 are parallel test work; subject-selection and VEX-placement implementation can proceed in separate files.
- Within US3, T041 and T042 are parallel stage-owned identity tests; T044 can proceed independently once stage contracts are stable.
- Within US4, T050–T052 are parallel test tasks, and T054 can proceed independently in cleanup files.
- After Phase 2, separate contributors can work on stage migration, storage backends, propagation, and validation tests, but deletion of transitional files (T027) must wait for all callers/tests to migrate.
- Polish review and regression checks (T059–T062) can run in parallel before the sequential repository-wide validation commands T063–T070.

---

## Parallel Example: User Story 1

```text
# After Phase 2, start independent stage, migration, storage, and test work:
Task: T012 — stage lifecycle tests in pkg/build/stage/artifact_test.go
Task: T013 — propagation tests in pkg/build/artifact_propagation_test.go
Task: T016 — migration coverage in pkg/build/
Task: T017 — StorageManager routing tests in pkg/build/stage/ and pkg/storage/manager/
Task: T020 — SbomStage in pkg/build/stage/sbom.go
Task: T021 — VexStage in pkg/build/stage/vex.go
Task: T015 — repository propagation scenarios in test/e2e/sbom/

# Integrate after the stage and storage contracts are stable:
Task: T022 — migrate SBOM behavior and callers
Task: T023 — migrate VEX behavior and callers
Task: T024 — enforce final-image OCI-artifact-only behavior
Task: T025 — register stages in pkg/build/build_phase.go
Task: T026 — remove duplicate AfterImages convergence
Task: T027 — delete transitional step files and tests
Task: T028 — implement shared StorageManager-routed propagation
```

## Implementation Strategy

### MVP First (User Story 1 Only)

1. Complete Phase 1 baseline inspection.
2. Complete Phase 2 `MutateArtifact`, checksum, `StorageManager`, final-image subject, propagation, and validation contracts.
3. Implement or verify `SbomStage` and `VexStage` as final-image-associated OCI-artifact stages.
4. Migrate all behavior and callers from `sbomStep`/`vexStep` through `MutateArtifact` and `StorageManager`.
5. Register the stages, connect primary/final/cache/secondary propagation, and delete transitional files.
6. Run US1 unit and SBOM e2e tests independently.
7. Stop for validation/demo before adding platform-specific and cache-invalidation refinements.

### Incremental Delivery

1. Deliver US1 as the first usable increment: lifecycle-owned artifact stages with complete `StorageManager`-routed repository propagation.
2. Add US2: correct final manifest/index subjects and platform placement, with stage-owned tests.
3. Add US3: complete stage dependency identity and cache reuse/invalidation.
4. Add US4: early validation and explicit final/cache failure behavior.
5. Run the full Polish phase and repository-required validation sequence.

### Traceability

- **FR-001–FR-003**: T020–T030, T037–T040
- **FR-004–FR-006**: T031–T040
- **FR-007–FR-010**: T007, T011–T013, T015–T030, T050, T054–T057
- **FR-011–FR-013**: T041–T049
- **FR-014–FR-016**: T003, T049, T054, T058
- **FR-017–FR-018**: T060–T062 and all implementation tasks; no CLI flag changes or OCI Referrers migration
- **Stage ownership and storage boundary**: T008–T013, T016–T027, T059–T061

## Notes

- Completed tasks retain `[X]`; pending tasks use `[ ]`. Every task has a sequential ID and story-phase tasks include exactly one `[US#]` label.
- No external API contracts were provided in `contracts/`; the artifact methods are internal `StorageManager` and `StagesStorage` contracts.
- The revised plan requires `SbomStage` and `VexStage` to be the sole lifecycle owners, associated with final image descriptors, and restricted to OCI-artifact operations through `MutateArtifact` and `StorageManager`; `MutateImage` remains reserved for image mutations.
- `sbom_step.go`, `vex_step.go`, their step-specific callers, and their tests must not remain after migration.
- No new dependencies, CLI flags, image layers, or OCI Referrers migration are planned.
