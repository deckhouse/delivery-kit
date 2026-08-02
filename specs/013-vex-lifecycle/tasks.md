---
description: "Task list for implementing VEX Lifecycle in werf.yaml (013-vex-lifecycle)"
---

# Tasks: VEX Lifecycle in werf.yaml

**Input**: Design documents from `/specs/013-vex-lifecycle/`

**Prerequisites**: plan.md (required), spec.md (required for user stories), research.md, data-model.md, contracts/config.md, contracts/oci-artifact.md

**Tests**: Test tasks are included per the Delivery Kit constitution (Test-Before-Merge). Tests use Ginkgo + Gomega and are co-located with source files.

**Organization**: Tasks are grouped by user story to enable independent implementation and testing.

## Format: `[ID] [P] [Story] Description`

- **[P]**: Can run in parallel (different files, no dependencies on incomplete tasks)
- **[Story]**: Which user story this task belongs to (US1, US2, US3)
- Include exact file paths in descriptions

## Path Conventions

- **Business logic**: `pkg/vex/` (NEW), `pkg/config/` (MODIFIED), `pkg/build/` (NEW)
- **Unit tests**: co-located with source files as `*_test.go`
- **E2E tests**: `test/e2e/vex/` (NEW)
- **Test helpers**: `test/pkg/`

## Build & Test Commands

- **Build**: `task build` (produces `./bin/werf`)
- **Unit tests**: `task test:unit -- -run TestAI_ ./pkg/...`
- **E2E tests**: `task test:e2e` with `paths="./pkg/..."` and `labelFilter="VEX"` (Ginkgo label filter)
- **Formatting**: `task format`

---

## Phase 1: Setup

**Purpose**: Create new package structure for VEX domain

- [X] T001 Create `pkg/vex/` and `pkg/vex/image/` package directories
- [X] T002 [P] Create `test/e2e/vex/` directory for e2e test suite

---

## Phase 2: Foundational — Config & Validation (Blocking Prerequisites)

**⚠️ CRITICAL**: No user story work can begin until this phase is complete

**Purpose**: Config parsing types and VEX document validation — needed by ALL user stories

- [X] T003 Create raw VEX config parsing type in `pkg/config/raw_vex.go` (mirrors `rawSbom` from `pkg/config/raw_sbom.go`)
- [X] T004 Create normalized Vex config type in `pkg/config/vex.go` (mirrors `Sbom` from `pkg/config/sbom.go`)
- [X] T005 [P] Add `RawVex *rawVex` field to `rawStapelImage` in `pkg/config/raw_stapel_image.go`
- [X] T006 [P] Add `RawVex *rawVex` field to `rawImageFromDockerfile` in `pkg/config/image_from_dockerfile.go`
- [X] T007 Add `Vex() *Vex` accessor method to normalized image types (stapel + dockerfile)
- [X] T008 Create VEX document validation utility `ValidateVEXDocument(data []byte) error` in `pkg/vex/vex.go` — validates OpenVEX JSON-LD format, file non-empty check

**Checkpoint**: Foundation ready — user story implementation can begin

---

## Phase 3: User Story 1 — Configure VEX File for an Image (Priority: P1) 🎯 MVP

**Goal**: A DevOps engineer can declare a `vex` field in werf.yaml. The build pipeline reads the VEX file from Git, validates it, and publishes it as an OCI artifact attached to the image manifest.

**Independent Test**: Add `vex: vex/my-app.openvex.json` to a single image in werf.yaml, run `werf build --repo <registry>`, and verify the VEX document appears as an OCI artifact attached to the image manifest in the registry.

### Tests for User Story 1

- [X] T009 [P] [US1] Unit test for `ValidateVEXDocument` in `pkg/vex/vex_test.go`
- [X] T010 [P] [US1] Unit test for raw VEX config parsing in `pkg/config/raw_vex_test.go`
- [X] T011 [P] [US1] Unit test for PushVEX in `pkg/vex/image/image_test.go`

### Implementation for User Story 1

- [X] T012 [P] [US1] Implement `PushVEX` in `pkg/vex/image/image.go` — reads VEX JSON, wraps in in-toto statement (predicate type `https://openvex.dev/ns/v0.2.0`), wraps in DSSE envelope, calls `OCIStore.Attach()` (see research.md §5 and contracts/oci-artifact.md)
- [X] T013 [US1] Create VEX build step in `pkg/build/vex_step.go` — mirrors `sbomStep` from `pkg/build/sbom_step.go`; reads VEX file from Git via giterminism manager, validates, calls `PushVEX`
- [X] T014 [US1] Integrate VEX step into build pipeline in `pkg/build/build_phase.go` — add `vexStep` field to `BuildPhase`, initialize in `NewBuildPhase`, add `convergeVexByImagesSets()` and `convergeImageVex()` methods (mirrors `convergeSbomByImagesSets`/`convergeImageSbom`), call from `AfterImages()` after SBOM converges
- [X] T015 [US1] Add file-tracking validation for VEX files in giterminism manager — read VEX file content from Git repository, verify it is tracked by Git (FR-003, FR-010)

**Checkpoint**: At this point, User Story 1 should be fully functional and testable independently

---

## Phase 4: User Story 2 — Update Existing VEX Document (Priority: P2)

**Goal**: A DevOps engineer modifies the VEX document in Git and rebuilds. The system detects the change, publishes an updated VEX OCI artifact, and replaces the previous version. When nothing changed, no new artifact is created (skip logic).

**Independent Test**: Configure a VEX file, build, then modify the VEX file content, rebuild, and verify the registry contains the new version. Then rebuild with no changes and verify no new artifact was created.

### Tests for User Story 2

- [X] T016 [P] [US2] Unit test for PullVEX in `pkg/vex/image/image_test.go`
- [X] T017 [P] [US2] Unit test for change detection and skip logic in `pkg/build/vex_step_test.go`

### Implementation for User Story 2

- [X] T018 [P] [US2] Implement `PullVEX` in `pkg/vex/image/image.go` — retrieves VEX artifact via `OCIStore.GetAttachedContent()`, unwraps DSSE envelope, unwraps in-toto statement, verifies predicate type, returns VEX JSON (see contracts/oci-artifact.md)
- [X] T019 [US2] Add checksum-based change detection to VEX build step — before publishing, call `PullVEX` and compare checksum annotation of existing artifact with current VEX file checksum; if identical, skip publish
- [X] T020 [US2] Implement image checksum binding in VEX build step — when image content changed but VEX file unchanged, still recreate VEX artifact because it is bound to image checksum (FR-011, Image-VEX Relationship Rules)

**Checkpoint**: User Stories 1 and 2 should now both work independently

---

## Phase 5: User Story 3 — Cleanup VEX Artifacts from Registry (Priority: P2)

**Goal**: A DevOps engineer runs registry cleanup. Stale or unreferenced VEX OCI artifacts are removed according to the same rules as SBOM artifacts.

**Independent Test**: Create multiple VEX artifact versions for an image, delete the image tag, run `werf cleanup`, and verify orphaned VEX artifacts are removed while active ones are retained.

### Implementation for User Story 3

- [X] T021 [US3] Add VEX predicate type constant (`VEXPredicateURI = "https://openvex.dev/ns/v0.2.0"`) to `pkg/vex/vex.go` (reuse from data-model.md constants)
- [X] T022 [US3] Verify SBOM cleanup path handles VEX artifacts — no separate cleanup code needed per research.md §6; VEX artifacts use the same DSSE envelope format and are cleaned up by the same fallback index and subject-reference mechanisms. Add VEX-aware filtering to fallback index `GetAttached()` calls if SBOM cleanup currently filters by predicate type to ensure VEX artifacts are included in scope.

**Checkpoint**: All user stories should now be independently functional

---

## Phase 6: Polish & Cross-Cutting Concerns

**Purpose**: E2E tests, documentation, and final verification

- [X] T023 [P] Create e2e test suite for VEX lifecycle in `test/e2e/vex/` — covers US1 (publish), US2 (update), US3 (cleanup), and all acceptance scenarios from spec.md using Ginkgo label `VEX`
- [X] T024 Run `task doc:gen` to regenerate CLI reference docs if any CLI help text was modified
- [X] T025 Final verification: run `task format && task build && task lint && task test:unit` — ensure all VEX-related code passes format, lint, build, and unit tests

---

## Phase 7: Convergence

**Purpose**: Close gaps identified by converge assessment — Git-tracking validation for VEX files and code quality cleanup

- [X] T026 Add `ReadVEXFile` method to giterminism manager's `FileReader` interface and implementation — reads VEX file content through `ReadAndCheckConfigurationFile`, validates file is tracked by Git (FR-003, FR-010, partial)
- [X] T027 Add `InspectConfigVexFilePath` method to giterminism manager's `Inspector` interface for VEX file path validation (FR-003)
- [X] T028 Update `convergeImageVex()` in `pkg/build/build_phase.go` to read VEX files via `giterminismManager.FileReader().ReadVEXFile()` instead of `os.ReadFile` (FR-003)
- [X] T029 Remove duplicate `ValidateVEXDocument(vexContent)` call at line 1637 of `pkg/build/build_phase.go` (unrequested)

---

## Dependencies & Execution Order

### Phase Dependencies

- **Setup (Phase 1)**: No dependencies — can start immediately
- **Foundational (Phase 2)**: Depends on Setup completion — BLOCKS all user stories
- **User Stories (Phase 3-5)**: All depend on Foundational phase completion
  - User stories proceed in priority order (US1 → US2 → US3)
  - US1 and US2 have some shared code paths but are independently testable
  - US3 depends on US1 for artifact publishing
- **Polish (Phase 6)**: Depends on all user stories being complete

### User Story Dependencies

- **User Story 1 (P1)**: Can start after Foundational (Phase 2) — No dependencies on other stories
- **User Story 2 (P2)**: Can start after Foundational (Phase 2) — Depends on PushVEX from US1 for PullVEX retrieval; change detection logic is independent
- **User Story 3 (P2)**: Can start after Foundational (Phase 2) — No code changes needed beyond US1; primarily verification

### Within Each User Story

- Tests MUST be written and FAIL before implementation
- Core types before business logic
- Business logic before pipeline integration
- Story complete before moving to next priority

### Parallel Opportunities

- All Setup tasks marked [P] can run in parallel
- All Foundational tasks marked [P] can run in parallel (within Phase 2)
- All tests for a user story marked [P] can run in parallel
- Types within a story marked [P] can run in parallel
- US1 and US2 could partially overlap (PushVEX and PullVEX are independent file operations)

---

## Parallel Example: User Story 1

```bash
# Launch all US1 tests together:
task test:unit -- -run "TestAI_ValidateVEXDocument" ./pkg/vex/
task test:unit -- -run "TestAI_RawVexConfig" ./pkg/config/
task test:unit -- -run "TestAI_PushVEX" ./pkg/vex/image/

# Launch parallel implementation tasks:
# T012: Implement PushVEX in pkg/vex/image/image.go
# T013: Create VEX build step in pkg/build/vex_step.go
# T015: Add giterminism file tracking for VEX
```

## Parallel Example: User Story 2

```bash
# Launch all US2 tests together:
task test:unit -- -run "TestAI_PullVEX" ./pkg/vex/image/
task test:unit -- -run "TestAI_VexSkipLogic" ./pkg/build/

# Launch parallel implementation tasks:
# T018: Implement PullVEX in pkg/vex/image/image.go
# T019: Add change detection to VEX build step
# T020: Image checksum binding
```

---

## Implementation Strategy

### MVP First (User Story 1 Only)

1. Complete Phase 1: Setup
2. Complete Phase 2: Foundational (CRITICAL — blocks all stories)
3. Complete Phase 3: User Story 1
4. **STOP and VALIDATE**: Test User Story 1 independently — VEX configured, published, attached
5. Deploy/demo if ready

### Incremental Delivery

1. Complete Setup + Foundational → Foundation ready
2. Add User Story 1 → Test independently → Deploy/Demo (MVP!)
3. Add User Story 2 → Test independently → Deploy/Demo
4. Add User Story 3 → Test independently → Deploy/Demo
5. Each story adds value without breaking previous stories

### VEX-Specific Implementation Order

The recommended implementation order within each phase:

**Foundational**: Config types first (T003-T004), then image integration (T005-T007), then validation (T008). Config parsing must be done before validation can use it.

**User Story 1**: PushVEX first (T012 — no dependencies on other components), then build step (T013 — depends on PushVEX), then pipeline integration (T014 — depends on build step), then giterminism (T015 — depends on read-from-Git in build step).

**User Story 2**: PullVEX first (T018 — independent), then change detection (T019 — depends on PullVEX), then image checksum binding (T020 — depends on change detection).

**User Story 3**: VEX predicate constant (T021 — trivial), then verify cleanup integration (T022 — no code changes expected beyond verification).

---

## Notes

- [P] tasks = different files, no dependencies
- [Story] label maps task to specific user story for traceability
- Each user story should be independently completable and testable
- Verify tests fail before implementing
- Commit after each task or logical group
- Stop at any checkpoint to validate story independently
- VEX mirrors SBOM pattern end-to-end (research.md §1) — use `pkg/sbom/` as reference
- No CLI commands needed for v1 (research.md §7)
- No meta-level toggle for v1 (research.md §4, FR-009)
- VEX uses SBOM cleanup rules — no separate cleanup code (research.md §6, FR-007)