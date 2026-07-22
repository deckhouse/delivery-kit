---
description: "Task list for reverting os-pm to inline syntax"
---

# Tasks: Not Enforce pm Determinism

**Input**: Design documents from `specs/009-not-enforce-pm-determinism/`

**Prerequisites**: plan.md (required), spec.md (required for user stories), research.md, data-model.md, contracts/

**Tests**: Test tasks are included where necessary to update existing test expectations. No new tests are required — this is a revert.

**Organization**: Tasks are grouped by user story to enable independent implementation and testing of each story.

## Path Conventions

- **Config layer**: `pkg/config/`
- **Build integration**: `pkg/build/`
- **SBOM**: `pkg/sbom/packages/os_pm/`
- **Managedinput**: `pkg/sbom/managedinput/`
- **E2E tests**: `test/e2e/sbom/`
- **E2E fixtures**: `test/e2e/sbom/_fixtures/`

## Build & Test Commands

- **Build**: `task build`
- **Unit tests**: `task test:unit paths="./pkg/..." -- -run TestName`
- **E2E tests**: `task test:e2e paths="./test/e2e/sbom/..." labelFilter="sbom && (packages || lifecycle || gost)"`
- **Linting**: `task lint:golangci-lint -- golangciPaths="./pkg/..."`

## Phase 1: Foundational (Config Layer)

**Purpose**: Restore the core data model and YAML parsing for `os-pm` inline syntax. These changes are the foundation for all downstream changes.

**⚠️ CRITICAL**: No user story work can begin until this phase is complete.

- [X] T001 Simplify `PackageEcosystem` struct: rename `DefaultSpec` → `DefaultSpecFile`, `DefaultLock` → `DefaultLockFile`, change `InstallCmd` signature to `func(workdir, specFile string, specList []string) string`; restore `PackagesSpec` struct, `normalizePackages()`, add `os-pm` to `ecosystems` registry in `pkg/config/packages_directive.go`
- [X] T002 Update `fillFileBasedSpec()` to set both `FileBased.Spec` (from `DefaultSpecFile`/`spec` YAML) and `Spec.Packages` (from `spec` YAML list) based on the ecosystem's `InstallCmd` signature in `pkg/config/raw_packages_directive.go`

**Checkpoint**: Config layer ready — `PackageEcosystem` simplified with unified `InstallCmd(workdir, specFile, specList)`, `os-pm` in unified registry, `PackagesSpec` restored, YAML parsing accepts `spec:` key as either file path or package list.

---

## Phase 2: User Story 1 - Declare OS packages inline (Priority: P1) 🎯 MVP

**Goal**: Users can declare OS packages inline in `werf.yaml` using `spec: [curl==8.12.1, jq]` syntax. The build generates a single command via `os-pm`'s `InstallCmd` that sets environment variables inline and runs `pm install curl==8.12.1 jq`. SBOM state is read from `/var/lib/pm/index.json` (maintained by `pm` itself) via `ReadFileFromImage`.

**Independent Test**: A build with `packages: [{type: os-pm, spec: [curl==8.12.1, jq]}]` generates a single command that includes env vars and `pm install curl==8.12.1 jq` (not `pm sync --from ...`).

#### Implementation for User Story 1

- [X] T003 [US1] Simplify `validate()` to check `Spec.Packages` for `os-pm` vs `FileBased.Workdir`/`FileBased.Spec` for file-based types in `pkg/config/packages_directive.go`
- [X] T004 [US1] Implement `os-pm`'s `InstallCmd` in `pkg/config/packages_commands.go` — composite command: `formatMkdirCommand()` (create dir), `formatVersionFileCommand()` (resolve PACKAGES_VERSION from secret/env, write to /var/lib/pm/container-factory-version), `formatInstallCommand()` (resolve PACKAGES_VERSION and REGISTRY as inline env vars, run `pm install <pkg_1> <pkg_2> ...`)
- [X] T005 [US1] Simplify `toDirective()` to pass `specList` (for `os-pm`) or `specFile` (for file-based) based on the ecosystem type in `pkg/config/raw_packages_directive.go`
- [X] T006 [US1] Remove `OSPMLockPath()` method, keep `HasOSPMPackages()` boolean in `pkg/config/stapel_image_base.go`
- [X] T007 [US1] Replace `osPmLockPath string` with `hasOsPmPackages bool` in `pkg/build/build_phase.go`
- [X] T008 [US1] Simplify `GeneratePackagesCommands()` to uniform `eco.InstallCmd(workdir, specFile, specList)` call for ALL types in `pkg/config/packages_commands.go`
- [X] T009 [US1] Replace `osPmLockPath string` with `osPmEnabled bool` in `ConvergeWithMerge()` signature, update `CollectBOM` call in `pkg/build/sbom_step.go`
- [X] T010 [US1] Rename `ParsePmLockJSON` → `ParsePmInstalledJSON`, remove `pmLockFile` struct, restore flat JSON parsing in `pkg/sbom/packages/os_pm/os_pm.go`
- [X] T011 [US1] Replace `collectPacketsFromLock` with `collectInstalledPackets` in `pkg/sbom/packages/os_pm/collect.go` — read `/var/lib/pm/index.json` via `ReadFileFromImage`
- [X] T012 [P] [US1] Revert `pkg/sbom/packages/os_pm/testdata/pm_info_installed.json` to flat format (remove `metadata`+`packages` envelope)
- [X] T013 [P] [US1] Update `pkg/sbom/packages/os_pm/os_pm_test.go` — rename `ParsePmLockJSON` references to `ParsePmInstalledJSON`, update empty-map test input

**Checkpoint**: At this point, User Story 1 should be fully functional. `os-pm` inline syntax works end-to-end: config parsing → command generation → build integration → SBOM collection.

---

## Phase 3: User Story 2 - No pm packages needed (Priority: P2)

**Goal**: A build without any `os-pm` directive produces no `pm install` commands and no os-pm SBOM processing. Non-pm package types (go-mod, etc.) are unaffected.

**Independent Test**: A build with `packages: [{type: go-mod, workdir: /, spec: go.mod}]` works correctly, and a build with no `packages` directive produces no pm commands.

#### Implementation for User Story 2

- [X] T014 [US2] Update `pkg/sbom/managedinput/managedinput_test.go` — update the `os-pm` entry to use the simplified `PackageEcosystem` fields
- [X] T015 [P] [US2] Remove `pm.yaml` and `pm.lock` files from all e2e fixture directories under `test/e2e/sbom/_fixtures/` (inject/, lifecycle/, negative/, packages_merge/, stage_deps/, stage_deps_file/, type_change/); restore explicit version constraints (e.g., `curl==8.12.1`, `jq==1.8.1`, `yq==4.48.1`, `tini==0.19.0`, `demo-app==1.0.0`) from removed `pm.yaml` files into the inline `spec:` list in `werf.yaml`
- [X] T016 [US2] Update e2e test expectations for inline model in `test/e2e/sbom/packages_test.go`, `test/e2e/sbom/lifecycle_test.go`, `test/e2e/sbom/gost_test.go`, `test/e2e/sbom/stage_dependencies_test.go`

**Checkpoint**: All user stories should now be independently functional.

---

## Phase 4: Refinements

**Purpose**: Apply corrections based on implementation review: add `ContainerFactoryVersionDir/File/IndexFile` constants, `envVarTmpl()` constructor and `format*` command decomposition, remove `ContainerFactoryVersionSnapshotCmd()`.

- [X] T017 Add constants in `pkg/config/packages_commands.go`: `ContainerFactoryVersionDir = "/var/lib/pm"`, `ContainerFactoryVersionFile = ContainerFactoryVersionDir + "/container-factory-version"`, `ContainerFactoryVersionIndexFile = ContainerFactoryVersionDir + "/index.json"
- [X] T018 Create `envVarTmpl(name string) string` in `pkg/config/packages_commands.go` — generates `name="${name:-$(<catBinPath> /run/secrets/<name> 2>/dev/null || true)}"` using `stapel.CatBinPath()`; no separate composer function needed since the three command segments are `;`-separated in the InstallCmd
- [X] T019 [P] Update `os-pm`'s `InstallCmd` in `pkg/config/packages_commands.go` — remove `pm info --installed --json` capture; compose command from `formatMkdirCommand()`, `formatVersionFileCommand()`, `formatInstallCommand()` using `envVarTmpl` for env var resolution; `pm` maintains `/var/lib/pm/index.json` itself
- [X] T020 [P] Update `collectInstalledPackets` in `pkg/sbom/packages/os_pm/collect.go` — read `/var/lib/pm/index.json` instead of previous path
- [X] T021 Add unit tests for env var constructor in `pkg/config/packages_commands_test.go` — test `envVarTmpl` template generation (PACKAGES_VERSION, REGISTRY) and full `os-pm` command composition (mkdir, version file, install)
- [X] T022 Remove `ContainerFactoryVersionSnapshotCmd()` function from `pkg/config/packages_commands.go` — the version file is now written as part of the `os-pm` InstallCmd itself
- [X] T023 Run `task test:unit` and fix any failures
- [ ] T024 Run `task test:e2e paths="./test/e2e/sbom/..."` and fix any failures

---

## Phase 5: Verification

**Purpose**: Ensure all tests pass after the refinements.

- [X] T025 Run `task test:unit` and fix any failures
- [ ] T026 Run `task test:e2e paths="./test/e2e/sbom/..."` and fix any failures

---

## Dependencies & Execution Order

### Phase Dependencies

- **Foundational (Phase 1)**: No dependencies — can start immediately
- **User Story 1 (Phase 2)**: Depends on Phase 1 completion
- **User Story 2 (Phase 3)**: Depends on Phase 1 completion
- **Refinements (Phase 4)**: Depends on Phase 2 and Phase 3 completion
- **Verification (Phase 5)**: Depends on Phase 4 completion

### User Story Dependencies

- **User Story 1 (P1)**: Can start after Foundational (Phase 1) — No dependencies on other stories
- **User Story 2 (P2)**: Can start after Foundational (Phase 1) — Independent of US1

### Within Each Phase

- Config layer changes first (T001-T002), then downstream consumers
- Within US1: command generation → build integration → SBOM → tests
- Within US2: managedinput test → e2e fixtures → e2e test expectations

### Parallel Opportunities

- T001 and T002 can be done in parallel (different files in same package, but touch different parts)
- T012 and T013 (test data) can be done in parallel with T003-T011
- T015 (fixtures) can be done in parallel with T014 and T016
- US1 and US2 can be done in parallel by different developers after Phase 1
- T019 and T020 can be done in parallel with T017-T018
- T021 (tests for env var constructor) depends on T018
- T022 depends on T017
- T023-T024 are sequential — fix unit tests first, then e2e
- T025-T026 are sequential — fix unit tests first, then e2e

---

## Implementation Strategy

### MVP First (User Story 1 Only)

1. Complete Phase 1: Foundational (T001-T002)
2. Complete Phase 2: US1 (T003-T013)
3. **STOP and VALIDATE**: Run `task test:unit` to verify US1 works
4. Deploy/demo if ready

### Incremental Delivery

1. Complete Phase 1 → Config layer foundation ready
2. Add US1 → Inline packages work end-to-end (MVP!)
3. Add US2 → Boundary cases and test updates
4. Verify all tests pass

### Parallel Team Strategy

With multiple developers:
1. Developer A: Phase 1 (T001-T002)
2. Once Phase 1 is done:
   - Developer A: US1 implementation (T003-T011)
   - Developer B: US1 test data (T012-T013) + US2 (T014-T016)
3. Both developers: Phase 4 refinements (T017-T024)
4. Both developers: Phase 5 verification (T025-T026)

---

## Notes

- [P] tasks = different files, no dependencies
- This feature simplifies `PackageEcosystem` with a unified `InstallCmd(workdir, specFile, specList)` for ALL ecosystem types — no special-casing for `os-pm`. Each ecosystem's `InstallCmd` encapsulates its own logic. SBOM state is read from `/var/lib/pm/index.json` (maintained by `pm` itself) via `ReadFileFromImage`. No separate capture command is needed.
- The `envVarTmpl(name string) string` constructor handles env var resolution with fallback to `/run/secrets/<name>` via `stapel.CatBinPath()` — each of the three command segments (mkdir, version file, install) uses it inline
- The `HasOSPMPackages()` method is PRESERVED — it existed before the 006 feature and is still needed.
- Commit after each task or logical group.