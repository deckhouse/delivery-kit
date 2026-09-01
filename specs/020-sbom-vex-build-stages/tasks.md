# Tasks: SBOM and VEX as Build Stages

**Input**: Design documents from `specs/020-sbom-vex-build-stages/`

**Prerequisites**: `plan.md`, `spec.md`, `research.md`, `data-model.md`, `quickstart.md`

**Tests**: Included because the feature specification requires independent testing for every user story. New tests must use co-located Ginkgo/Gomega suites and existing e2e fixtures.

## Phase 1: Setup (Shared Infrastructure)

**Purpose**: Establish the implementation baseline without changing user-facing CLI semantics.

- [X] T001 Inventory existing stage, SBOM, VEX, artifact, storage-copy, and cleanup call paths in `pkg/build/`, `pkg/build/stage/`, `pkg/oci/artifact/`, `pkg/storage/manager/`, and `pkg/cleaning/`, recording the concrete integration points in `specs/020-sbom-vex-build-stages/`
- [X] T002 [P] Inspect existing SBOM and VEX unit/e2e fixture conventions in `pkg/build/`, `test/e2e/sbom/`, and `test/e2e/vex/` and identify reusable helpers without adding a second test harness
- [X] T003 [P] Confirm the existing fallback-tag artifact index and cleanup compatibility expectations in `pkg/oci/artifact/` and `pkg/cleaning/` before modifying propagation code

---

## Phase 2: Foundational (Blocking Prerequisites)

**Purpose**: Define the minimal internal contracts shared by both artifact stages.

**Checkpoint**: The shared stage metadata, descriptor propagation shape, and early registry validation are understood and available before story implementation begins.

- [X] T004 Define internal artifact-stage metadata and stage-name constants in `pkg/build/stage/base.go`, including artifact kind, parent descriptor, target platform, mutable flag, and non-buildable flag
- [X] T005 Define the kind-neutral artifact propagation operation and source/destination descriptor data flow in `pkg/build/` using existing `pkg/oci/artifact/` and `pkg/storage/manager/` primitives, without introducing a public API or new dependency
- [X] T006 Locate the earliest common build initialization path and specify the registry-backed-storage validation seam in `pkg/build/build_phase.go` for both SBOM-enabled and VEX-enabled builds
- [X] T007 [P] Add shared test fixtures or helper functions needed to construct manifest/index descriptors and fallback artifact indexes in co-located files under `pkg/build/` and `pkg/oci/artifact/`

---

## Phase 3: User Story 1 - Artifacts follow published images (Priority: P1) 🎯 MVP

**Goal**: Replace the transitional SBOM/VEX steps with lifecycle-owned stages and make all attached artifacts follow images into primary, final, cache, and secondary-restored destinations.

**Independent Test**: Build the existing fixture with primary-only, final, cache, combined final/cache, identical-address, and secondary-repository configurations; retrieve both artifact kinds by each destination image digest.

### Tests for User Story 1

- [X] T008 [US1] Add Ginkgo/Gomega unit coverage for artifact-stage mutability, non-buildability, parent descriptor requirements, and stage lifecycle behavior in `pkg/build/stage/artifact_test.go`
- [ ] T009 [US1] Add Ginkgo/Gomega unit coverage for shared propagation, destination digest resolution, identical-repository skipping, and artifact identity deduplication in `pkg/build/artifact_propagation_test.go`
- [ ] T010 [US1] Add Ginkgo/Gomega unit coverage for secondary-to-primary restoration and missing-source-artifact handling in `pkg/build/artifact_propagation_test.go`
- [ ] T011 [US1] Extend the SBOM e2e suite in `test/e2e/sbom/` for primary-only, final, cache, combined final/cache, identical-address, and secondary-repository artifact availability scenarios
- [ ] T012 [US1] Add Ginkgo/Gomega migration coverage proving all SBOM callers use `SbomStage` and all VEX callers use `VexStage`, with no `sbomStep` or `vexStep` references remaining in `pkg/build/`

### Implementation for User Story 1

- [X] T013 [P] [US1] Implement the registry-only mutable, non-buildable `SbomStage` in `pkg/build/stage/sbom.go`, including SBOM generation, cache identity, signing, attestation publication, and fallback-index interaction
- [X] T014 [P] [US1] Implement the registry-only mutable, non-buildable `VexStage` in `pkg/build/stage/vex.go`, including VEX generation, cache identity, signing, attestation publication, and fallback-index interaction
- [ ] T015 [US1] Migrate all behavior and callers from `sbomStep` into `SbomStage` in `pkg/build/`, preserving existing SBOM generation, checksum, signing, and publication behavior
- [ ] T016 [US1] Migrate all behavior and callers from `vexStep` into `VexStage` in `pkg/build/`, preserving existing VEX generation, checksum, signing, and publication behavior
- [ ] T017 [US1] Register `SbomStage` and `VexStage` after the content-producing stage for Stapel, Dockerfile, and restored-stage image paths in `pkg/build/build_phase.go`
- [ ] T018 [US1] Execute artifact publication through stage `MutateImage` without changing image filesystem or layer content, and remove duplicate SBOM/VEX generation from `BuildPhase.AfterImages` while retaining unrelated publication/report work in `pkg/build/build_phase.go`
- [ ] T019 [US1] Delete transitional `pkg/build/sbom_step.go`, `pkg/build/vex_step.go`, and their step-specific tests after all callers and migration tests use `SbomStage` and `VexStage`
- [X] T020 [US1] Implement shared idempotent artifact propagation with destination descriptor resolution, identical-address skipping, fallback-index deduplication, and all-artifact copying in `pkg/build/artifact_propagation.go`
- [X] T021 [US1] Connect primary-to-final and primary-to-cache image-copy paths to the shared propagation operation while preserving fatal final errors and best-effort cache warnings in `pkg/build/` and `pkg/storage/manager/`
- [X] T022 [US1] Connect secondary-stage restoration into primary storage to the same propagation operation, including explicit handling when a source artifact is absent, in `pkg/storage/manager/` and `pkg/build/`

**Checkpoint**: User Story 1 is independently functional; `SbomStage` and `VexStage` are the sole lifecycle owners and artifacts follow every applicable published image.

---

## Phase 4: User Story 2 - Platform-specific artifacts describe the correct image (Priority: P1)

**Goal**: Attach per-platform SBOMs to platform manifests and attach exactly one image-level VEX to the correct single-platform manifest or multi-platform index.

**Independent Test**: Build a two-platform fixture, inspect each artifact subject and platform metadata, and verify that multi-platform VEX appears only on the image index while single-platform VEX uses the manifest.

### Tests for User Story 2

- [X] T023 [P] [US2] Add Ginkgo/Gomega unit tests for single-platform and multi-platform subject selection in `pkg/build/artifact_subject_test.go`
- [X] T024 [P] [US2] Add Ginkgo/Gomega unit tests proving platform SBOM metadata and parent digest are distinct per platform in `pkg/build/sbom_step_test.go`
- [ ] T025 [US2] Move or rename platform-subject tests from transitional `pkg/build/sbom_step_test.go` into the stage-owned test location and ensure the final suite contains no step-specific test dependency
- [ ] T026 [US2] Extend `test/e2e/sbom/` with two-platform subject and metadata assertions for each platform manifest
- [X] T027 [US2] Extend `test/e2e/vex/` with single-platform manifest placement and multi-platform index-only placement assertions

### Implementation for User Story 2

- [X] T028 [US2] Implement explicit artifact subject resolution for published manifest and index descriptors in `pkg/build/artifact_subject.go`
- [ ] T029 [US2] Pass the target platform and resolved platform manifest descriptor through `SbomStage` creation and publication in `pkg/build/stage/sbom.go` and `pkg/build/build_phase.go`
- [ ] T030 [US2] Make `VexStage` registration run once per multi-platform image set with the top-level index subject, and use the image manifest subject for single-platform builds in `pkg/build/stage/vex.go` and `pkg/build/build_phase.go`
- [X] T031 [US2] Ensure propagation resolves the corresponding destination platform manifest or image index before attaching artifacts, including destinations with differing source digests, in `pkg/build/artifact_propagation.go`

**Checkpoint**: User Story 2 is independently testable and no artifact can silently use an index subject for a platform SBOM or duplicate multi-platform VEX onto platform manifests.

---

## Phase 5: User Story 3 - Rebuilds reuse or invalidate artifact results correctly (Priority: P1)

**Goal**: Preserve valid artifact cache hits while preventing stale reuse when image, scanner, merge/GOST, VEX document, platform, format, or signing inputs change; cache ownership lives in the artifact stages.

**Independent Test**: Repeat unchanged builds and then change each effective artifact input one at a time; inspect cache decisions, artifact identities, and duplicate fallback-index entries.

### Tests for User Story 3

- [X] T032 [P] [US3] Add Ginkgo/Gomega tests for `SbomStage` dependency identity across image digest, scanner, merge/GOST, format, signer, and target-platform inputs in `pkg/build/stage/sbom_test.go`
- [X] T033 [P] [US3] Add Ginkgo/Gomega tests for `VexStage` dependency identity across parent digest, document content, format, and signer inputs in `pkg/build/stage/vex_test.go`
- [X] T034 [US3] Add Ginkgo/Gomega tests for repeated idempotent publication and cache-restored artifact processing in `pkg/build/artifact_propagation_test.go`
- [ ] T035 [US3] Extend `test/e2e/sbom/` and `test/e2e/vex/` with unchanged rebuild, changed-input, signing-identity, and restored-cache scenarios
- [ ] T036 [US3] Remove or migrate any remaining cache-identity assertions from deleted `pkg/build/sbom_step_test.go` and `pkg/build/vex_step_test.go` into stage-owned tests

### Implementation for User Story 3

- [X] T037 [US3] Include all effective SBOM inputs and the parent image identity in `SbomStage` dependency calculation while preserving existing checksum semantics in `pkg/build/stage/sbom.go`
- [X] T038 [US3] Include VEX document content, parent descriptor identity, format version, and signer identity in `VexStage` dependency calculation in `pkg/build/stage/vex.go`
- [ ] T039 [US3] Select reusable artifact-bearing stages from primary and secondary storage using the complete dependency identity, and apply identical processing to locally built and cache-restored images in `pkg/build/` and `pkg/storage/manager/`
- [X] T040 [US3] Preserve fallback-index convergence and prevent duplicate entries during repeated or concurrent artifact publication in `pkg/oci/artifact/` and `pkg/build/artifact_propagation.go`

**Checkpoint**: User Story 3 is independently testable; unchanged inputs reuse artifacts and every effective changed input invalidates only the affected artifact identity.

---

## Phase 6: User Story 4 - Registry failures have predictable consequences (Priority: P2)

**Goal**: Reject unsupported local-only artifact builds early, fail on final-repository artifact errors, and retain distinguishable best-effort behavior for cache errors.

**Independent Test**: Exercise unavailable final and cache repositories, missing secondary artifacts, concurrent attachment, and no-registry builds; verify build result and actionable diagnostics.

### Tests for User Story 4

- [X] T041 [P] [US4] Add Ginkgo/Gomega unit tests proving artifact-enabled local-only builds fail before any image stage executes in `pkg/build/build_phase_test.go`
- [X] T042 [P] [US4] Add Ginkgo/Gomega unit tests for fatal final propagation errors and non-fatal, clearly logged cache propagation errors in `pkg/build/artifact_propagation_test.go`
- [X] T043 [P] [US4] Add Ginkgo/Gomega concurrency tests that retain every fallback-index artifact entry during concurrent attachment in `pkg/oci/artifact/`
- [ ] T044 [US4] Extend `test/e2e/sbom/` and `test/e2e/vex/` for unavailable final/cache repositories, local-only rejection, and missing secondary source artifact behavior
- [X] T045 [US4] Extend cleanup coverage in `pkg/cleaning/` and relevant e2e fixtures to verify orphan fallback artifact indexes are removed from primary and propagated repositories

### Implementation for User Story 4

- [X] T046 [US4] Add earliest-phase registry-backed-storage validation for enabled SBOM/VEX with an actionable `--repo` or disable-artifacts message in `pkg/build/build_phase.go`
- [X] T047 [US4] Enforce fatal final-repository publication/propagation errors and best-effort cache-repository warnings through one shared error-policy path in `pkg/build/artifact_propagation.go` and `pkg/storage/manager/`
- [X] T048 [US4] Ensure missing secondary source artifacts return an incomplete/error result rather than claiming artifact-complete restoration in `pkg/build/` and `pkg/storage/manager/`
- [X] T049 [US4] Verify artifact propagation does not bypass existing cleanup and purge behavior, updating only the necessary repository traversal in `pkg/cleaning/`

**Checkpoint**: User Story 4 is independently testable; registry failures and local-only configuration produce predictable results without changing repository flag semantics.

---

## Phase 7: Polish & Cross-Cutting Concerns

**Purpose**: Validate the complete implementation against the revised stage-ownership boundary and repository quality gates.

- [X] T050 [P] Review `pkg/build/`, `pkg/build/stage/`, `pkg/storage/manager/`, `pkg/oci/artifact/`, and `pkg/cleaning/` for unnecessary public surface, duplicate convergence paths, unwrapped errors, and comments that do not explain non-obvious logic
- [ ] T051 [P] Verify no `sbomStep` or `vexStep` types, constructors, callers, or compatibility wrappers remain in `pkg/build/`, and verify no step-specific tests remain after migration
- [ ] T052 [P] Verify existing builds with SBOM/VEX disabled and existing `--repo`, `--final-repo`, `--cache-repo`, and `--secondary-repo` semantics in `test/legacy_e2e/` and relevant unit fixtures
- [X] T053 Run formatting with `task format` for authored Go directories
- [X] T054 Run compilation with `task build`
- [X] T055 Install the lint prerequisite with `task deps:install:golangci-lint` and run repository lint with `task lint`
- [ ] T056 Run the complete unit suite with `task test:unit`
- [X] T057 Run scoped SBOM e2e coverage with `task test:e2e paths="./test/e2e/sbom/..." labelFilter="sbom"`
- [X] T058 Run scoped VEX e2e coverage with `task test:e2e paths="./test/e2e/vex/..." labelFilter="vex"`
- [ ] T059 Run legacy integration coverage with `task test:integration`
- [X] T060 Confirm authored-file whitespace and generated-file scope with `git diff --check` limited to changed authored files, without modifying `CHANGELOG.md` or generated CLI reference files

---

## Dependencies & Execution Order

### Phase Dependencies

- **Phase 1 (Setup)**: No implementation dependency; establishes the current call-path baseline.
- **Phase 2 (Foundational)**: Depends on Phase 1 and blocks all user story implementation.
- **Phase 3 (US1)**: Depends on Phase 2 and is the MVP increment. It now includes full migration from `sbomStep`/`vexStep` and deletion of the transitional files.
- **Phase 4 (US2)**: Depends on US1's artifact stages and propagation path because it specializes subject selection; platform tests must be owned by the new stages before old step tests are deleted.
- **Phase 5 (US3)**: Depends on US1 and US2 stage identity/subject contracts so cache identity includes the correct parent descriptor.
- **Phase 6 (US4)**: Depends on the shared propagation operation from US1; its validation work can proceed in parallel with US2/US3 after the shared path exists.
- **Phase 7 (Polish)**: Depends on all desired stories being complete, including removal of transitional files and references.

### User Story Dependencies

- **US1 (P1)**: Starts after Phase 2; no dependency on another user story. MVP.
- **US2 (P1)**: Depends on US1's `SbomStage`/`VexStage` lifecycle and shared propagation implementation.
- **US3 (P1)**: Depends on US1's stages and US2's explicit parent-subject rules.
- **US4 (P2)**: Depends on US1's propagation/error path; early-validation tests can proceed independently of US2 and US3.

### Parallel Opportunities

- Phase 1 tasks T002 and T003 can run in parallel after T001's baseline inventory.
- Within US1, T013 and T014 are parallel stage files; T009 and T012 can be developed as separate test concerns before integration. T015 and T016 are parallel migrations when their callers are disjoint.
- Within US2, T023/T024 and T026/T027 are parallel test work; subject-selection implementation and VEX placement implementation can proceed in separate files.
- Within US3, T032 and T033 are parallel stage-owned identity tests; T035 can proceed independently once stage contracts are stable.
- Within US4, T041, T042, and T043 are parallel test tasks, and T045 can proceed independently in cleanup files.
- After Phase 2, separate contributors can work on stage migration, propagation, and validation tests, but deletion of transitional files (T019) must wait for all callers/tests to migrate.
- Polish review and disabled-feature regression checks (T050–T052) can run in parallel before the sequential repository-wide validation commands T053–T060.

---

## Parallel Example: User Story 1

```text
# After Phase 2, start independent stage, migration, and test work:
Task: T008 — stage lifecycle tests in pkg/build/stage/artifact_test.go
Task: T009 — propagation tests in pkg/build/artifact_propagation_test.go
Task: T012 — migration coverage in pkg/build/
Task: T013 — SbomStage in pkg/build/stage/sbom.go
Task: T014 — VexStage in pkg/build/stage/vex.go
Task: T011 — repository propagation scenarios in test/e2e/sbom/

# Integrate after the stage contracts are stable:
Task: T015 — migrate SBOM behavior and callers
Task: T016 — migrate VEX behavior and callers
Task: T017 — register stages in pkg/build/build_phase.go
Task: T018 — remove duplicate AfterImages convergence
Task: T019 — delete transitional step files and tests
```

## Implementation Strategy

### MVP First (User Story 1 Only)

1. Complete Phase 1 baseline inspection.
2. Complete Phase 2 shared stage and propagation contracts.
3. Implement or verify `SbomStage` and `VexStage`.
4. Migrate all behavior and callers from `sbomStep`/`vexStep`.
5. Register the stages, connect primary/final/cache/secondary propagation, and delete the transitional files.
6. Run US1 unit and SBOM e2e tests independently.
7. Stop for validation/demo before adding platform-specific and cache-invalidation refinements.

### Incremental Delivery

1. Deliver US1 as the first usable increment: lifecycle-owned artifact stages with complete repository propagation.
2. Add US2: correct manifest/index subjects and platform placement, with stage-owned tests.
3. Add US3: complete stage dependency identity and cache reuse/invalidation.
4. Add US4: early validation and explicit final/cache failure behavior.
5. Run the full Polish phase and repository-required validation sequence.

### Traceability

- **FR-001–FR-003**: T013–T022, T028–T031
- **FR-004–FR-006**: T023–T031
- **FR-007–FR-010**: T009–T022, T042, T046–T048
- **FR-011–FR-013**: T032–T040
- **FR-014–FR-016**: T003, T040, T045, T049
- **FR-017–FR-018**: T051–T052 and all implementation tasks; no CLI flag changes or OCI Referrers migration
- **Stage ownership boundary**: T012, T015, T016, T019, T025, T036, and T051

## Notes

- Completed tasks retain `[X]`; pending tasks use `[ ]`. Both are valid Markdown checkbox markers and every task has a sequential ID.
- No external API contracts were provided in `contracts/`; the propagation contract remains internal to `pkg/build`.
- The revised plan requires `SbomStage` and `VexStage` to be the sole lifecycle owners; `sbom_step.go`, `vex_step.go`, their step-specific callers, and their tests must not remain after migration.
- No new dependencies, CLI flags, image layers, or OCI Referrers migration are planned.
