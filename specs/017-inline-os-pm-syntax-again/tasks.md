---
description: "Task list for Inline os-pm Syntax (reverting 015)"
---

# Tasks: Inline os-pm Syntax

**Input**: Design documents from `/specs/017-inline-os-pm-syntax-again/`

**Prerequisites**: plan.md (required), spec.md (required for user stories), research.md, data-model.md, contracts/

**Tests**: Test tasks are included — the spec explicitly requires test updates (FR-017, FR-018) and test-driven verification per constitution (Principle IV).

**Organization**: Tasks are grouped by user story to enable independent implementation and testing of each story.

## Format: `[ID] [P?] [Story] Description`

- **[P]**: Can run in parallel (different files, no dependencies)
- **[Story]**: Which user story this task belongs to (e.g., US1, US2, US3)
- Include exact file paths in descriptions

## Path Conventions

- **CLI commands**: `cmd/werf/<domain>/`
- **Business logic**: `pkg/<domain>/`
- **Unit tests**: co-located with source files as `*_test.go`
- **AI-written tests**: `*_ai_test.go` with `TestAI_` prefix
- **E2E tests**: `test/e2e/<domain>/`
- **Test helpers**: `test/pkg/`

## Build & Test Commands

- **Build**: `task build` (produces `./bin/werf`)
- **Unit tests**: `task test:unit -- -run TestMyFunc ./pkg/...`
- **E2E tests**: `task test:e2e` with `paths="./test/e2e/..."` and `labelFilter="..."` (Ginkgo label filter). NEVER place `KEY=VALUE` after `--` separator.
  - Environment is pre-configured — `task test:setup:environment` has already been executed. Do not skip e2e tests citing environment setup.
- **Formatting**: `task format`

---

## Phase 1: Setup (Shared Infrastructure)

**Purpose**: Project initialization — no new packages, but config package adjustments needed for the revert.

- [X] T001 Create feature branch `017-inline-os-pm-syntax-again` and verify clean checkout

---

## Phase 2: Foundational (Blocking Prerequisites)

**Purpose**: Core revert of config parsing — inline spec list for `os-pm`, removal of file-based path, updated ecosystem entry. MUST be complete before ANY user story.

**⚠️ CRITICAL**: No user story work can begin until this phase is complete

- [X] T002 [P] Restore `PackagesSpec` struct with `Packages []string` in `pkg/config/packages_directive.go` and add `const OsPMCatalogerName = "os-pm-cataloger"`
- [X] T003 [P] Update `PackageEcosystem.InstallCmd` signature in `pkg/config/packages_directive.go`: change from `func(workdir, specFile, lockFile string, env map[string]string) string` to `func(workdir string, files FileBasedSpec, pkgs []string, env map[string]string) string`
- [X] T004 [P] Update the `os-pm` ecosystem entry in `pkg/config/packages_directive.go`: set `DefaultSpecFile: ""`, `DefaultLockFile: ""`, switch `CatalogerName` to `OsPMCatalogerName`, and update `InstallCmd` to `pm install <pkgs>`
- [X] T005 [P] Restore inline spec list parsing in `pkg/config/raw_packages_directive.go`: skip `fillFileBasedSpec` for `os-pm` type; convert `spec` from `[]interface{}` to `[]string` in `toDirective` when `type == "os-pm"`; add validation to reject string-path spec (SC-009), empty lists (FR-003), and `workdir` for os-pm (FR-004)
- [X] T006 [P] Add `formatInstallCommand(pkgs []string, env map[string]string) string` in `pkg/config/packages_commands.go` that generates `pm install <pkg1> <pkg2> ...` with preamble (mkdir, version file) and inline env vars
- [X] T007 [P] Remove `OSPMLockPath()` and `OSPMSpecPath()` from `pkg/config/stapel_image_base.go`; restore `HasOSPMPackages() bool` method
- [X] T008 [P] Update `raw_stapel_image.go` if it references removed methods — should call `HasOSPMPackages()` instead

**Checkpoint**: Foundation ready — user story implementation can now begin in parallel

---

## Phase 3: User Story 1 — Declare OS packages inline, multiple sections (Priority: P1) 🎯 MVP

**Goal**: Users declare `os-pm` packages inline in `werf.yaml` as a list of strings. Multiple `os-pm` sections are supported, each with optional `env`. Each section generates a separate `pm install <pkgs>` command.

**Independent Test**: `task test:unit paths="./pkg/config/..."` — config parsing, command generation, and validation tests all pass with inline `spec: [curl, jq]` syntax.

### Tests for User Story 1 ⚠️

> **NOTE: Write these tests FIRST, ensure they FAIL before implementation**

- [X] T009 [P] [US1] Update `pkg/config/raw_packages_directive_test.go`: change os-pm entries from `"spec": "pm.yaml"` to `"spec": ["curl", "jq"]`; invert the "os-pm with list spec is rejected" test to assert acceptance; add cases for empty spec rejection, string-path rejection, workdir rejection, env preservation
- [X] T010 [P] [US1] Update `pkg/config/packages_directive_javascript_test.go`: update os-pm entries in combined config tests to use inline `spec` list syntax
- [X] T011 [P] [US1] Update `pkg/config/packages_commands_test.go`: assert `pm install curl==8.12.1 jq` instead of `pm sync --from pm.lock`; add test for multiple sections generating multiple commands; add test for env vars passed inline
- [X] T012 [P] [US1] Update `pkg/config/stapel_image_base_test.go`: test `HasOSPMPackages()` instead of `OSPMLockPath()`; add test for true/false cases

### Implementation for User Story 1

- [X] T013 [P] [US1] Implement `PackagesSpec` restoration, `OsPMCatalogerName` constant, and updated ecosystem entry in `pkg/config/packages_directive.go` (depends on T002, T003, T004)
- [X] T014 [P] [US1] Implement inline spec list parsing, validation, and `fillFileBasedSpec` skip for os-pm in `pkg/config/raw_packages_directive.go` (depends on T005)
- [X] T015 [P] [US1] Implement `formatInstallCommand` in `pkg/config/packages_commands.go` (depends on T006)
- [X] T016 [P] [US1] Implement `HasOSPMPackages()` restoration and removal of `OSPMLockPath`/`OSPMSpecPath` in `pkg/config/stapel_image_base.go` (depends on T007)

**Checkpoint**: At this point, User Story 1 should be fully functional and testable independently — `task test:unit paths="./pkg/config/..."` passes

---

## Phase 4: User Story 2 — SBOM from final state in image (Priority: P1)

**Goal**: After all pm commands execute, the system reads `/var/lib/pm/index.json` from inside the built image to produce the SBOM. The `collect.go` is restored, `PMBOMPatcher` is deleted, and the build phase is updated to pass a boolean flag instead of a lock file path.

**Independent Test**: `task test:unit paths="./pkg/sbom/..." -- -focus="os-pm"` — SBOM collection tests pass, `CollectBOM` reads from image.

### Tests for User Story 2 ⚠️

> **NOTE: Write these tests FIRST, ensure they FAIL before implementation**

- [X] T017 [P] [US2] Add unit tests for `CollectBOM` in `pkg/sbom/packages/os_pm/collect_test.go`: test reading from image, parsing, `containerFactoryVersion` fallback, empty index.json handling
- [X] T018 [P] [US2] Update `pkg/build/stage/packages_test.go`: update os-pm entries to use inline spec syntax instead of file-based references

### Implementation for User Story 2

- [X] T019 [P] [US2] Restore `CollectBOM` in `pkg/sbom/packages/os_pm/collect.go`: read `/var/lib/pm/index.json` from image via `ReadFileFromImage`, parse via `ParsePmInstalledJSON`, convert via `ConvertToCycloneDX`, resolve `containerFactoryVersion` from env then image
- [X] T020 [P] [US2] Delete `pkg/sbom/packages/os_pm/pm_bom_patcher.go` and its test `pkg/sbom/packages/os_pm/pm_bom_patcher_test.go` (FR-011)
- [X] T021 [US2] Update `pkg/build/build_phase.go`: replace `osPmLockPath`/`osPmSpecPath` fields with `hasOsPmPackages bool`; remove `PMBOMPatcher` creation
- [X] T022 [US2] Update `pkg/build/sbom_step.go`: change `ConvergeWithMerge` parameter from `osPmLockPath string` to `osPmEnabled bool`; inject `CollectBOM` result after syft scan and before GOST upsert

**Checkpoint**: At this point, User Stories 1 AND 2 should both work independently — config parsing, command generation, SBOM collection, and build phase tests pass

---

## Phase 5: User Story 3 — No os-pm packages needed (Priority: P2)

**Goal**: When no `os-pm` packages are declared, no pm commands are generated and no os-pm SBOM processing occurs.

**Independent Test**: A config with no `packages` or non-`os-pm` packages only: `HasOSPMPackages()` returns false, no pm commands, no `CollectBOM` call.

### Tests for User Story 3 ⚠️

> **NOTE: Write these tests FIRST, ensure they FAIL before implementation**

- [X] T023 [P] [US3] Update `pkg/sbom/managedinput/managedinput_test.go`: verify `os-pm` is still skipped by syft cataloger derivation, update test data for inline syntax
- [X] T024 [P] [US3] Add `HasOSPMPackages()` negative test in `pkg/config/stapel_image_base_test.go`: config with no packages → false; config with non-os-pm packages only → false

### Implementation for User Story 3

- [X] T025 [P] [US3] Verify `managedinput` skip of os-pm in `pkg/sbom/managedinput/managedinput.go` — no change needed per plan (already correct), but ensure `OsPMCatalogerName` constant is used for comparison
- [X] T026 [US3] Verify `pkg/build/stage/packages.go` — no change needed per plan (stage wiring is unchanged; commands are generated at config parse time)

**Checkpoint**: All user stories should now be independently functional

---

## Phase 6: E2E Tests & Polish

**Purpose**: End-to-end tests and final cleanup.

- [X] T027 [P] Update e2e test fixtures under `test/e2e/sbom/_fixtures/`: revert `pm.yaml`/`pm.lock` files to inline `spec` list syntax; delete `pm.yaml` and `pm.lock` fixture files (FR-018)
- [X] T028 Verify no references to `PMBOMPatcher` remain: `grep -r "PMBOMPatcher" pkg/sbom/` returns no hits
- [X] T029 Verify no remaining `pm.lock` references in os-pm code paths: `grep -r "pm.lock" pkg/config/ pkg/build/ pkg/sbom/` returns hits only for non-os-pm types
- [X] T030 [P] Run `task format` across changed packages: `pkg/config/`, `pkg/build/`, `pkg/sbom/`, `test/e2e/`
- [X] T031 Run `task build` and verify binary compiles
- [X] T032 Run `task test:unit paths="./pkg/config/..."` and verify all config tests pass
- [X] T033 Run `task test:unit paths="./pkg/sbom/..."` and verify all SBOM tests pass
- [X] T034 Run `task test:unit paths="./pkg/build/..."` and verify all build tests pass
- [~] T035 Run `task test:unit` (full suite) — 1 pre-existing failure in `cyclonedxutil` (unrelated to changes)
- [X] T036 Run `task test:e2e paths="./test/e2e/sbom/..." labelFilter="os-pm"` — all `packages`-labeled tests pass (12/12)
- [X] T037 Run `task test:e2e paths="./test/e2e/sbom/..." labelFilter="packages"` — all 12 package-related e2e tests pass
- [X] T038 [P] Clean up: delete `pm.yaml`/`pm.lock` fixture files; update all remaining fixtures using old file-based syntax

---

## Dependencies & Execution Order

### Phase Dependencies

- **Setup (Phase 1)**: No dependencies — can start immediately
- **Foundational (Phase 2)**: Depends on Setup completion — BLOCKS all user stories
- **User Stories (Phase 3-5)**: All depend on Foundational phase completion
  - US1 (Phase 3) and US2 (Phase 4) are independent of each other once foundational is complete
  - US3 (Phase 5) depends only on Foundational — can run in parallel with US1 and US2
- **E2E & Polish (Phase 6)**: Depends on all user stories being complete

### User Story Dependencies

- **User Story 1 (P1)**: Can start after Foundational (Phase 2) — No dependencies on other stories
- **User Story 2 (P1)**: Can start after Foundational (Phase 2) — Independent of US1; both are P1 priority
- **User Story 3 (P2)**: Can start after Foundational (Phase 2) — Independent of US1 and US2

### Within Each User Story

- Tests MUST be written and FAIL before implementation
- Core types before business logic
- Business logic before build pipeline integration
- Story complete before moving to next priority

### Parallel Opportunities

- All Foundational tasks marked [P] can run in parallel (within Phase 2)
- Once Foundational phase completes, US1, US2, and US3 can all start in parallel
- All tests for a user story marked [P] can run in parallel
- Implementation tasks within a story marked [P] can run in parallel
- Different user stories can be worked on in parallel by different team members

---

## Parallel Example: User Story 1

```bash
# Launch all tests for User Story 1 together:
task test:unit paths="./pkg/config/..." -- -focus="os-pm"
task test:unit paths="./pkg/config/packages_commands_test.go"
task test:unit paths="./pkg/config/stapel_image_base_test.go"

# Launch all implementation tasks for User Story 1 together:
# T013: Restore PackagesSpec in packages_directive.go
# T014: Inline spec parsing in raw_packages_directive.go
# T015: formatInstallCommand in packages_commands.go
# T016: HasOSPMPackages in stapel_image_base.go
```

## Parallel Example: User Story 2

```bash
# Launch all tests for User Story 2 together:
task test:unit paths="./pkg/sbom/..." -- -focus="os-pm"
task test:unit paths="./pkg/build/stage/packages_test.go"

# Launch all implementation tasks for User Story 2 together:
# T019: Restore CollectBOM in collect.go
# T020: Delete PMBOMPatcher and its test
# T021: Update build_phase.go
# T022: Update sbom_step.go
```

---

## Implementation Strategy

### MVP First (User Story 1 Only)

1. Complete Phase 1: Setup
2. Complete Phase 2: Foundational (CRITICAL — blocks all stories)
3. Complete Phase 3: User Story 1 (config parsing, command generation)
4. **STOP and VALIDATE**: Test User Story 1 independently — `task test:unit paths="./pkg/config/..."`
5. Deploy/demo if ready

### Incremental Delivery

1. Complete Setup + Foundational → Foundation ready
2. Add User Story 1 (Config: inline parsing) → Test independently → Deploy/Demo (MVP!)
3. Add User Story 2 (SBOM: CollectBOM from image) → Test independently → Deploy/Demo
4. Add User Story 3 (No os-pm: graceful degredation) → Test independently → Deploy/Demo
5. Each story adds value without breaking previous stories
6. Final: E2E tests and full validation

### Parallel Team Strategy

With multiple developers:

1. Team completes Phase 1 + Phase 2 together
2. Once Foundational is done:
   - Developer A: User Story 1 (config parsing changes)
   - Developer B: User Story 2 (SBOM collection changes)
   - Developer C: E2E test fixture updates (can start early)
3. User Story 3 is a low-effort verification task
4. Stories complete and integrate independently; Phase 6 validates everything together

---

## Notes

- [P] tasks = different files, no dependencies
- [Story] label maps task to specific user story for traceability
- Each user story should be independently completable and testable
- Verify tests fail before implementing
- Commit after each task or logical group
- Stop at any checkpoint to validate story independently
- Avoid: vague tasks, same file conflicts, cross-story dependencies that break independence
- **Key revert files**: `packages_directive.go`, `raw_packages_directive.go`, `packages_commands.go`, `stapel_image_base.go`, `build_phase.go`, `sbom_step.go`, `collect.go`, `pm_bom_patcher.go` (delete)