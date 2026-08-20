---

description: "Implementation tasks for rejecting PM_LOCK_FILE overrides"
---

# Tasks: reject PM_LOCK_FILE override

**Input**: Design documents from `/specs/018-reject-pm-lock-file-env/`

**Prerequisites**: plan.md, spec.md, research.md, data-model.md, contracts/configuration.md, quickstart.md

**Organization**: Tasks are grouped by user story. The feature uses the existing Go configuration and SBOM infrastructure; no new dependency or project initialization is required.

## Path Conventions

- **Configuration logic**: `pkg/config/`
- **Configuration tests**: co-located `*_test.go` files in `pkg/config/`
- **SBOM metadata**: `pkg/sbom/os_pm/metadata/`

## Build & Test Commands

- **Formatting**: `task format`
- **Build**: `task build`
- **Lint prerequisite**: `task deps:install:golangci-lint`
- **Lint**: `task lint`
- **Focused unit tests**: `task test:unit paths="./pkg/config/..." -- -focus="PM_LOCK_FILE|os-pm"`
- **Configuration unit tests**: `task test:unit paths="./pkg/config/..."`
- **SBOM unit tests**: `task test:unit paths="./pkg/sbom/os_pm/..."`
- **E2E**: run a scoped `task test:e2e` command with both `paths` and `labelFilter`
- **Integration**: `task test:integration`

---

## Phase 1: Setup (Shared Infrastructure)

**Purpose**: Confirm the existing project structure is sufficient for this focused validation change.

- [X] T001 Confirm the existing `pkg/config` validation and co-located Ginkgo test structure are used without adding dependencies in `pkg/config/packages_directive.go`

---

## Phase 2: Foundational (Blocking Prerequisites)

**Purpose**: No new foundational infrastructure is required; the existing `metadata.ContainerFactoryIndexPath` invariant and package directive conversion path are the shared prerequisites.

**Checkpoint**: Existing configuration parsing and SBOM metadata packages are available for story implementation.

---

## Phase 3: User Story 1 - Reject an SBOM-breaking PM path override (Priority: P1) 🎯 MVP

**Goal**: Reject every `PM_LOCK_FILE` declaration on an `os-pm` package directive during configuration validation, while preserving unrelated environment variables and other package types.

**Independent Test**: Parse `os-pm` configurations containing custom, default, relative, and empty `PM_LOCK_FILE` values and verify validation fails with an error naming `PM_LOCK_FILE` and `/var/lib/pm/index.json`; parse configurations without the key and configurations for other package types and verify they remain accepted.

### Tests for User Story 1

- [X] T002 [P] [US1] Add table-driven Ginkgo/Gomega validation cases for custom, default-path, relative, and empty `PM_LOCK_FILE` values through the parsed YAML helper in `pkg/config/raw_packages_directive_test.go`
- [X] T003 [P] [US1] Add acceptance cases for an `os-pm` directive without `PM_LOCK_FILE`, an unrelated `os-pm` environment variable, and an unrelated environment variable on a non-`os-pm` directive in `pkg/config/raw_packages_directive_test.go`
- [X] T004 [US1] Assert that each rejected parsed configuration reports both `PM_LOCK_FILE` and `metadata.ContainerFactoryIndexPath` in `pkg/config/raw_packages_directive_test.go`

### Implementation for User Story 1

- [X] T005 [US1] Add an `os-pm`-scoped map-key presence check for `PM_LOCK_FILE` in `pkg/config/packages_directive.go`
- [X] T006 [US1] Return an actionable validation error explaining that the `pm` SBOM state must remain at `metadata.ContainerFactoryIndexPath` in `pkg/config/packages_directive.go`
- [X] T007 [US1] Verify the validation check remains before package command generation by preserving the `rawPackagesDirective.toDirective` validation boundary in `pkg/config/raw_packages_directive.go`

**Checkpoint**: User Story 1 independently prevents SBOM-breaking configuration before build or package installation and leaves unaffected configurations unchanged.

---

## Phase 4: User Story 2 - Preserve the fixed SBOM source path (Priority: P1)

**Goal**: Keep `/var/lib/pm/index.json` as the sole effective `pm` SBOM state path and prevent explicit default-path or empty-value declarations from creating an override.

**Independent Test**: Verify accepted `os-pm` configuration still maps to the existing SBOM cataloger metadata and that `metadata.ContainerFactoryIndexPath` remains `/var/lib/pm/index.json`; verify explicit default-path and empty `PM_LOCK_FILE` declarations are rejected by validation.

### Tests for User Story 2

- [X] T008 [P] [US2] Extend the co-located metadata test to assert the fixed `ContainerFactoryIndexPath` remains `/var/lib/pm/index.json` in `pkg/sbom/os_pm/metadata/metadata_test.go`
- [X] T009 [P] [US2] Add a regression case confirming accepted `os-pm` configuration retains the metadata-backed cataloger registration in `pkg/config/packages_directive_test.go`
- [X] T010 [US2] Add parsed configuration cases for explicit `/var/lib/pm/index.json` and empty `PM_LOCK_FILE` values that verify no value is accepted as an override in `pkg/config/raw_packages_directive_test.go`

### Implementation for User Story 2

- [X] T011 [US2] Reuse `metadata.ContainerFactoryIndexPath` in the validation error and do not introduce a configurable or duplicate SBOM path in `pkg/config/packages_directive.go`
- [X] T012 [US2] Verify the `pm` cataloger continues to consume `metadata.ContainerFactoryIndexPath` without path changes in `pkg/sbom/os_pm/metadata/metadata.go`

**Checkpoint**: User Story 2 independently guarantees the fixed SBOM source path and rejects both explicit-default and empty-value attempts to configure a path override.

---

## Phase 5: Polish & Cross-Cutting Concerns

**Purpose**: Run focused and repository-required quality gates without changing unrelated behavior.

- [X] T013 [P] Run focused configuration and SBOM unit tests using `task test:unit paths="./pkg/config/..." -- -focus="PM_LOCK_FILE|os-pm"` and `task test:unit paths="./pkg/sbom/os_pm/..."` after changes to `pkg/config/raw_packages_directive_test.go` and `pkg/sbom/os_pm/metadata/metadata_test.go`
- [X] T014 Run `task format` and inspect the resulting changes in `pkg/config/packages_directive.go`, `pkg/config/raw_packages_directive.go`, `pkg/config/raw_packages_directive_test.go`, `pkg/config/packages_directive_test.go`, and `pkg/sbom/os_pm/metadata/metadata_test.go`
- [X] T015 Run `task build` and `task deps:install:golangci-lint` to validate the implementation in `pkg/config/packages_directive.go`
- [ ] T016 Run `task lint` and the full `task test:unit` suite to validate all authored Go files and regression behavior
- [ ] T017 Run a scoped `task test:e2e` command with `paths` and `labelFilter` covering the affected configuration/SBOM behavior, then run `task test:integration` against the prepared environment

---

## Dependencies & Execution Order

### Phase Dependencies

- **Setup (Phase 1)**: T001 confirms the existing structure; no project initialization is needed.
- **Foundational (Phase 2)**: Uses existing configuration and metadata infrastructure; it blocks no additional setup tasks.
- **User Story 1 (Phase 3)**: Depends on T001; T002-T004 should be written before T005-T007 and should fail before the implementation is added.
- **User Story 2 (Phase 4)**: Depends on T001 and the shared validation behavior from T005-T006; its metadata regression checks can be prepared in parallel with US1 tests, but final execution depends on the implementation.
- **Polish (Phase 5)**: Depends on both user stories being implemented and their focused tests passing.

### User Story Dependencies

- **User Story 1 (P1)**: Can start after T001; it is the MVP and owns the validation behavior.
- **User Story 2 (P1)**: Can prepare tests after T001, but relies on the validation error/path reuse introduced for US1; it remains independently testable through metadata and parsed configuration assertions.

### Parallel Opportunities

- T002 and T003 can be written in parallel because they add separate table entries in the same test file only if coordinated to avoid conflicting edits; otherwise run them sequentially.
- T008 and T009 can be prepared in parallel because they affect different test files.
- T013 and code review of the generated test cases can proceed in parallel after implementation; final gates remain ordered.
- No story-specific implementation tasks are safely parallelizable because T005-T006 share the same validation branch and error contract.

---

## Implementation Strategy

### MVP First (User Story 1 Only)

1. Complete T001 and confirm no setup changes are needed.
2. Add T002-T004 and verify the new cases fail before implementation.
3. Complete T005-T007.
4. Run T013 and stop for independent MVP validation.

### Incremental Delivery

1. Complete User Story 1 to block unsafe `PM_LOCK_FILE` configuration.
2. Complete User Story 2 to lock the fixed SBOM path and protect against explicit default/empty values.
3. Run Phase 5 repository quality gates before handoff.

## Notes

- Every task uses the required checklist format with a sequential ID.
- Story tasks carry `[US1]` or `[US2]`; setup, foundational, and polish tasks do not.
- No new external dependency, CLI help text, generated file, or documentation update is required by this feature.
