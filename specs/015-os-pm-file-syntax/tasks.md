# Tasks: os-pm File-Based Syntax

**Input**: Design documents from `/specs/015-os-pm-file-syntax/`

**Prerequisites**: plan.md (required), spec.md (required for user stories), research.md, data-model.md, contracts/

**Tests**: No test tasks requested in the specification. Test tasks are only included for User Stories 2 and 3 where the independent test criteria require verification of already-working behavior.

**Organization**: Tasks are grouped by user story to enable independent implementation and testing of each story.

## Format: `[ID] [P?] [Story] Description`

- **[P]**: Can run in parallel (different files, no dependencies on incomplete tasks)
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
- **Formatting**: `task format`

---

## Phase 1: Setup

**Purpose**: Verify the development environment and understand the current codebase state

- [ ] T001 Read and understand current `PackagesDirective` struct in `pkg/config/packages_directive.go`
- [ ] T002 Run `task build` to confirm a clean starting point before making changes

---

## Phase 2: Foundational (Blocking Prerequisites)

**Purpose**: Core structural changes that ALL user stories depend on

**⚠️ CRITICAL**: No user story work can begin until this phase is complete

### Task Descriptions

These tasks transform the `os-pm` package type from inline-syntax (`spec: [curl, jq]`) to file-based (`spec: "pm.yaml"`, `lock: "pm.lock"`). They remove the `PackagesSpec` struct, register the `os-pm` ecosystem entry with file-based defaults, and de-specialize the remaining `os-pm`-specific branches in config parsing and validation.

- [ ] T003 Remove `PackagesSpec` struct from `pkg/config/packages_directive.go`; remove `Spec PackagesSpec` field from `PackagesDirective` struct; remove or simplify `normalizePackages()` if it exists; update any direct references to `Spec.Packages` in the same file
- [ ] T004 [P] Register `os-pm` in the `ecosystems` map in `pkg/config/packages_directive.go` with `DefaultSpecFile: "pm.yaml"`, `DefaultLockFile: "pm.lock"`, `CatalogerName: "os-pm-lock-cataloger"`, and a new `InstallCmd` that generates `pm sync --from <lockfile>` (preceded by mkdir and container factory version snapshot commands). The signature must receive the lock file path for the `--from` flag. (Depends on T003 — `InstallCmd` signature may reference removed `specList` parameter.)
- [ ] T005 [P] De-specialize `fillFileBasedSpec()` in `pkg/config/raw_packages_directive.go`: remove the `os-pm`-specific inline-spec branch; ensure `os-pm` uses the common `FileBasedSpec` resolution path with defaults `spec: "pm.yaml"`, `lock: "pm.lock"`; reject `workdir` for `os-pm` with validation error; validate that `spec` field for `os-pm` is a string (file path), rejecting list values
- [ ] T006 De-specialize `validate()` in `pkg/config/packages_directive.go`: remove the `os-pm`-specific inline-spec validation branch; add `os-pm` validation that rejects `workdir` with `"workdir is not supported for type \"os-pm\""`; add validation requiring `lock` file existence (when spec file exists)
- [ ] T007 [P] Change `HasOSPMPackages()` → `OSPMLockPath()` in `pkg/config/stapel_image_base.go` — return the lock file path (relative to repo root, e.g., `"pm.lock"`) for the first `os-pm` directive, or empty string if no `os-pm` packages; update all callers in `pkg/config/`, `pkg/build/builder/`, and `pkg/sbom/managedinput/`

**Checkpoint**: Foundation ready — the `os-pm` type is registered with file-based defaults, old inline syntax is rejected, and the lock file path flows through the builder interface.

---

## Phase 3: User Story 1 — Declare OS packages via pm.yaml / pm.lock (Priority: P1) 🎯 MVP

**Goal**: A user can declare OS packages by adding `packages: [{type: os-pm}]` to their `werf.yaml`, placing `pm.yaml` and `pm.lock` at the repository root. The build generates `pm sync --from <lockfile>` (with container factory version snapshot) and SBOM scans `pm.yaml` and `pm.lock` from the build context.

**Independent Test**: A build directive with `os-pm` pointing to a `pm.yaml`/`pm.lock` pair runs `pm sync --from pm.lock` inside the build container and installs the locked packages correctly.

### Implementation for User Story 1

- [ ] T008 [US1] Update the `InstallCmd` for `os-pm` in the `ecosystems` map in `pkg/config/packages_directive.go`: generate `pm sync --from <lockfile>` instead of `pm install <pkg_1> ... <pkg_N>`; preserve the existing container factory version snapshot command before the `pm sync` command; no `cd <workdir>` prefix needed for `os-pm`
- [ ] T009 [P] [US1] Wire up SBOM cataloger for `os-pm` in `pkg/sbom/managedinput/managedinput.go`: ensure the cataloger name `"os-pm-lock-cataloger"` resolves source paths `pm.yaml` and `pm.lock` (at the repository root, no `workdir` prefix); verify no special-casing is needed — the `CatalogerName` field in the ecosystem entry and `FileBasedSpec` already provide the necessary data
- [ ] T010 [US1] Add lock file existence validation in `validate()` in `pkg/config/packages_directive.go`: when `os-pm` spec file exists (e.g., `pm.yaml`), require that the lock file (e.g., `pm.lock`) also exists; error message: `"pm.lock not found at <path>. Run 'pm lock' in your repository to generate the lock file, commit it, and retry."`
- [ ] T011 [US1] Update `GeneratePackagesCommands()` in `pkg/config/packages_commands.go` if needed: ensure the lock file path is passed to `InstallCmd` instead of the old `specList` parameter; the function should resolve `pkg.FileBased.Lock` and pass it as the lock file parameter

**Checkpoint**: At this point, User Story 1 should be fully functional — `os-pm` with file-based syntax generates correct `pm sync` commands, SBOM scans the spec/lock files, and missing lock file fails with a clear error.

---

## Phase 4: User Story 2 — stageDependencies triggers packages stage on spec/lock changes (Priority: P1)

**Goal**: When the user configures `git.stageDependencies.packages` to track `pm.yaml` and `pm.lock`, changes to those files invalidate the packages stage and trigger re-execution.

**Independent Test**: A build with `pm.lock` tracked by `git.stageDependencies.packages` produces a cache hit when nothing changes, and a cache miss (packages stage re-execution) when `pm.lock` is updated.

> **Note**: Per research (Unknown 3), the `stageDependencies.packages` mechanism already works for all file-based package types. No code changes are needed — this phase verifies the behavior with unit tests.

### Verification for User Story 2

- [ ] T012 [P] [US2] Add or update unit test in `pkg/build/stage/packages_test.go` verifying that `pm.yaml` and `pm.lock` tracked by `git.stageDependencies.packages` correctly invalidate the packages stage when their content changes; verify cache hit on unchanged files
- [ ] T013 [P] [US2] Add or update unit test in `pkg/config/raw_packages_directive_test.go` (or a new test file) verifying that the `stageDependencies.packages` field can reference `pm.yaml` and `pm.lock` for `os-pm` type

**Checkpoint**: User Story 2 is verified — stage dependencies correctly track `pm.yaml`/`pm.lock` changes and trigger packages stage re-execution.

---

## Phase 5: User Story 3 — No os-pm packages needed (Priority: P2)

**Goal**: A build without any `os-pm` directive produces no `pm sync` commands and no os-pm SBOM processing.

**Independent Test**: A build without any `os-pm` directive produces no `pm sync` commands and no os-pm SBOM processing.

> **Note**: This is a boundary case that should be automatically satisfied by the design. This phase verifies the behavior.

### Verification for User Story 3

- [ ] T014 [P] [US3] Add or update unit test in `pkg/config/packages_commands_test.go` verifying that `GeneratePackagesCommands()` returns empty when no `os-pm` packages are defined, or when only non-`os-pm` types (e.g., `go-mod`) are present
- [ ] T015 [P] [US3] Add or update unit test in `pkg/sbom/managedinput/managedinput_test.go` verifying that `ToCatalogers()` returns no os-pm cataloger when no `os-pm` packages are present

**Checkpoint**: User Story 3 is verified — the system degrades gracefully when `os-pm` is not used.

---

## Phase 6: Polish & Cross-Cutting Concerns

**Purpose**: Update all existing tests and test fixtures that reference the old inline `os-pm` syntax, and verify everything passes together.

- [ ] T016 [P] Update `raw_packages_directive_test.go` in `pkg/config/`: replace all inline `spec: [curl, jq]` and `spec: [curl]` test fixtures with file-based syntax (`spec: "pm.yaml"`, `lock: "pm.lock"`); update assertions from `PackagesSpec{Packages: ...}` to `FileBased.Spec`/`FileBased.Lock`; add test cases for new validation (workdir rejection, spec-as-string rejection for lists)
- [ ] T017 [P] Update `packages_commands_test.go` in `pkg/config/`: replace all `pm install` command assertions with `pm sync --from <lockfile>` assertions; update `GeneratePackagesCommands os-pm` test block; update env var test blocks to use file-based syntax
- [ ] T018 [P] Update `packages_directive_javascript_test.go` in `pkg/config/`: replace inline `os-pm` syntax in combined config test entries with file-based syntax
- [ ] T019 [P] Update `managedinput_test.go` in `pkg/sbom/managedinput/`: add or update test cases for the `"os-pm-lock-cataloger"` cataloger name and source paths `["pm.yaml", "pm.lock"]`
- [ ] T020 `task format && task build && task test:unit` — run full validation on all changed packages to confirm everything compiles and passes

---

## Dependencies & Execution Order

### Phase Dependencies

- **Setup (Phase 1)**: No dependencies — can start immediately
- **Foundational (Phase 2)**: Depends on Setup — BLOCKS all user stories
- **User Story 1 (Phase 3)**: Depends on Foundational (Phase 2) — begins after T007
- **User Story 2 (Phase 4)**: Depends on Foundational (Phase 2) — no code changes needed, only verification tests
- **User Story 3 (Phase 5)**: Depends on Foundational (Phase 2) — no code changes needed, only verification tests
- **Polish (Phase 6)**: Depends on Phases 2-5 being complete (test updates must reflect final code state)

### User Story Dependencies

- **User Story 1 (P1)**: Can start after Foundational (Phase 2) — No dependencies on other stories
- **User Story 2 (P1)**: Can start after Foundational (Phase 2) — independent of US1 and US3
- **User Story 3 (P2)**: Can start after Foundational (Phase 2) — independent of US1 and US2

> **Note**: US2 and US3 require no code changes (the behavior already works or is naturally handled by the foundational changes). They consist primarily of verification tests.

### Within Each User Story

- Core types before business logic
- Business logic before verification tests
- Story complete before moving to next priority

### Parallel Opportunities

- All tasks marked [P] within the same phase can run in parallel

---

## Parallel Example: User Story 1

```bash
# Launch InstallCmd update and SBOM wiring together:
Go file: "pkg/config/packages_directive.go"  (T006)
Go file: "pkg/sbom/managedinput/managedinput.go"  (T007)
```

## Parallel Example: Polish Phase

```bash
# Launch all test updates together:
task test:unit -- -run TestRawPackagesDirective ./pkg/config/...
task test:unit -- -run TestGeneratePackagesCommands ./pkg/config/...
task test:unit -- -run TestToCatalogers ./pkg/sbom/managedinput/...
```

---

## Implementation Strategy

### MVP First (User Story 1 Only)

1. Complete Phase 1: Setup
2. Complete Phase 2: Foundational (CRITICAL — blocks all stories)
3. Complete Phase 3: User Story 1
4. **STOP and VALIDATE**: Test User Story 1 independently
5. Deploy/demo if ready

### Incremental Delivery

1. Complete Setup + Foundational → Foundation ready
2. Add User Story 1 → Test independently → **MVP Ready!**
3. Add User Story 2 (verification tests only) → Test independently
4. Add User Story 3 (verification tests only) → Test independently
5. Polish: Update all remaining test files → Full test suite passes

### Test Update Strategy

Test updates are deferred to Phase 6 to avoid working against the old test expectations while refactoring. If any existing test breaks during Phases 2-3, fix that specific test immediately (it indicates an unintended behavior change) rather than deferring to Phase 6.

---

## Notes

- [P] tasks = different files, no dependencies on incomplete tasks
- [Story] label maps task to specific user story for traceability
- Each user story should be independently completable and testable
- Verify tests fail before implementing (tests in Phases 4-5 are verification tests, not TDD)
- Commit after each task or logical group
- Stop at any checkpoint to validate story independently
- Avoid: vague tasks, same file conflicts, cross-story dependencies that break independence