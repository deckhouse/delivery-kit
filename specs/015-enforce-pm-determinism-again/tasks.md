# Tasks: os-pm File-Based Syntax

**Input**: Design documents from `/specs/015-enforce-pm-determinism-again/`

**Prerequisites**: plan.md (required), spec.md (required for user stories), research.md, data-model.md, contracts/

**Tests**: The examples below include test tasks. Tests are included because the feature specification defines explicit acceptance scenarios and success criteria that require test validation.

**Organization**: Tasks are grouped by user story to enable independent implementation and testing of each story.

## Format: `[ID] [P?] [Story] Description`

- **[P]**: Can run in parallel (different files, no dependencies)
- **[Story]**: Which user story this task belongs to (e.g., US1, US2, US3)
- Include exact file paths in descriptions

## Path Conventions

- **CLI commands**: `cmd/werf/<domain>/`
- **Business logic**: `pkg/<domain>/`
- **Build phase**: `pkg/build/` (build_phase.go, sbom_step.go)
- **Unit tests**: co-located with source files as `*_test.go`
- **E2E tests**: `test/e2e/<domain>/`
- **Test helpers**: `test/pkg/`

## Build & Test Commands

- **Build**: `task build` (produces `./bin/werf`)
- **Unit tests**: `task test:unit -- -run TestMyFunc ./pkg/...`
- **E2E tests**: `task test:e2e` with `paths="./test/e2e/..."` and `labelFilter="..."` (Ginkgo label filter). NEVER place `KEY=VALUE` after `--` separator.
- **Formatting**: `task format`

---

## Phase 1: Setup (Shared Infrastructure)

**Purpose**: Study existing code paths, understand the current os-pm implementation and build-phase integration, and prepare for changes.

- [X] T001 Study existing os-pm code paths in `pkg/config/packages_directive.go` — understand the current `ecosystems` entry, `InstallCmd`, `HasOSPMPackages()`, `validate()`, and `fillFileBasedSpec()` branches
- [X] T002 Study existing build-phase SBOM integration in `pkg/build/build_phase.go` and `pkg/build/sbom_step.go` — understand how `convergeImageSbom()` extracts `OSPMLockPath()`, reduces it to `hasOsPmPackages bool`, and passes to `ConvergeWithMerge()`. Understand existing patcher pattern
- [X] T003 Study existing os-pm test fixtures and test files — understand current test structure for inline `spec: [pkg...]` syntax across all unit test files, e2e fixtures, and e2e Go test files

---

## Phase 2: Foundational (Blocking Prerequisites)

**Purpose**: Core config model changes that MUST be complete before ANY user story can be implemented. These are the structural changes to the packages directive model, ecosystems registry, validation logic, and build-phase plumbing.

**⚠️ CRITICAL**: No user story work can begin until this phase is complete

- [X] T004 Remove `PackagesSpec` struct from `pkg/config/packages_directive.go` — remove the struct definition and the `Spec PackagesSpec` field from `PackagesDirective`
- [X] T005 Remove `normalizePackages()` function from `pkg/config/packages_directive.go` (if it exists)
- [X] T006 [P] Register `os-pm` in the `ecosystems` map in `pkg/config/packages_directive.go` with `DefaultSpecFile: "pm.yaml"`, `DefaultLockFile: "pm.lock"`, `CatalogerName: "os-pm-lock-cataloger"`
- [X] T007 [P] Update `InstallCmd` for `os-pm` in `pkg/config/packages_directive.go` to generate `pm sync --from <lockfile>` (preceded by container factory version preamble: `mkdir -p /var/lib/pm` and container factory version file write), using `formatSyncCommand()` instead of `formatInstallCommand()`. The `workdir` parameter is ignored (always empty for os-pm), `specList` is unused (file-based), and the lock file path comes from `PackagesDirective.FileBased.Lock`
- [X] T008 De-specialize `fillFileBasedSpec()` in `pkg/config/raw_packages_directive.go` — remove the special-cased os-pm branch that resolves inline `spec: [...]` lists. The os-pm type now uses the same `FileBasedSpec` resolution path as all other package types
- [X] T009 De-specialize `validate()` in `pkg/config/packages_directive.go` — remove the special-cased os-pm validation branch. The os-pm type validates using standard `FileBasedSpec` rules with type-specific overrides
- [X] T010 Add `workdir` rejection for os-pm in `pkg/config/raw_packages_directive.go` — when type is `os-pm` and `workdir` is set, return validation error: `"workdir is not supported for type \"os-pm\""`
- [X] T011 Add inline spec list rejection for os-pm in `pkg/config/raw_packages_directive.go` — when type is `os-pm` and `spec` is a list (not a string), return validation error: `"unsupported packages spec type %T for type \"os-pm\"; spec must be a string"`
- [X] T012 Add `OSPMLockPath()` method to `StapelImageBase` in `pkg/config/stapel_image_base.go` — replace the current `HasOSPMPackages() bool` with `OSPMLockPath() string` that returns the lock file path (e.g., `"pm.lock"`) for the first `os-pm` directive, or empty string if no os-pm packages. Update all callers of `HasOSPMPackages()` in `pkg/build/`

**Checkpoint**: Foundation ready — core config model changed, ecosystems registry updated, validation rules established, builder interface updated with lock path.

---

## Phase 3: User Story 1 — Declare OS packages via pm.yaml / pm.lock (Priority: P1) 🎯 MVP

**Goal**: A user declares `packages: [{type: os-pm}]` in `werf.yaml`, and when `pm.yaml`/`pm.lock` files exist at the repository root, the build correctly: (a) runs `pm sync --from pm.lock` inside the build container, (b) propagates the lock path through the build phase, (c) enriches host-scanned PM components with `containerFactoryVersion` PURL qualifier.

**Independent Test**: A build directive with `os-pm` pointing to a `pm.yaml`/`pm.lock` pair generates the correct `pm sync --from pm.lock` command. The build phase receives the lock path string. SBOM integration parses `pm.lock` from build context via delivery-kit's own parser and enriches components via BOMPatcher.

### Implementation for User Story 1

- [X] T013 [US1] Add missing `pm.lock` validation error in `pkg/sbom/packages/os_pm/pm_bom_patcher.go` — when `pm.yaml` exists but `pm.lock` is missing in the commit tree, fail with error: `"pm.lock not found at <path>. Run 'pm lock' in your repository to generate the lock file, commit it, and retry."` (implemented in PM BOMPatcher during build phase, following the same pattern as gomod spec file checking)
- [X] T014 [US1] Update `convergeImageSbom()` in `pkg/build/build_phase.go` — change from passing `hasOsPmPackages bool` to passing `ospmLockPath string` (from `imageBase.OSPMLockPath()`) to `ConvergeWithMerge()`
- [X] T015 [US1] Update `ConvergeWithMerge()` signature in `pkg/build/sbom_step.go` — replace `osPmEnabled bool` parameter with `osPmLockPath string`. Use the lock path to conditionally enable PM-specific processing
- [X] T016 [US1] Implement PM BOMPatcher — create `pkg/sbom/packages/os_pm/pm_bom_patcher.go` with a patcher function that: (a) reads container factory version from inside the built image via `readContainerFactoryVersion()` (reusing `pkg/sbom/packages/os_pm/collect.go`), (b) iterates SBOM components matching `syft:package:foundBy = "os-pm-lock-cataloger"`, (c) appends `containerFactoryVersion=<version>` PURL qualifier. Wire the patcher into `ConvergeWithMerge()` in `pkg/build/sbom_step.go`
- [X] T017 [P] [US1] Integrate os-pm SBOM via delivery-kit's own pm.lock parser in `pkg/sbom/packages/os_pm/` — the existing `ParsePmLock()` and `collectPacketsFromLock()` functions (preserved, NOT dead code) parse `pm.lock` from build context. Hook these into the SBOM collection pipeline so that `CollectBOM()` produces components from `pm.lock` instead of from inside the image. Update `collect.go` to remove the `collectInstalledPackets()` call (handled in dead code cleanup phase)
- [X] T018 [P] [US1] Implement FR-012 in `pkg/sbom/managedinput/managedinput.go` — `buildResolvers()` SHALL NOT derive a syft cataloger for `os-pm`. The `CatalogerName` in the ecosystems entry is preserved for delivery-kit's own SBOM metadata (not for syft). Added a type-based check in `buildResolvers()` to skip `PackagesDirectiveTypeOSPM`. `pm.lock` is parsed by delivery-kit's own code (PM BOMPatcher), not by syft
- [X] T019 [US1] Update inline os-pm syntax tests in `pkg/config/raw_packages_directive_test.go` — migrate all `"os-pm with inline spec list"`, `"os-pm with single package in spec"`, `"os-pm without packages"` tests to file-based syntax (`spec: "pm.yaml"`, `lock: "pm.lock"`). Remove the special inline `PackagesSpec` assertion patterns (e.g., `Expect(packages[i].Spec.Packages).To(...)`) and replace with `FileBased` assertions
- [X] T020 [US1] Update os-pm command generation tests in `pkg/config/packages_commands_test.go` — migrate the `"GeneratePackagesCommands os-pm"` block from `pm install` assertions to `pm sync --from pm.lock` assertions. Update env var test blocks to use file-based syntax
- [X] T021 [US1] Update combined config parsing tests in `pkg/config/packages_directive_javascript_test.go` — migrate the `"go-mod + javascript-npm + os-pm combined config parses correctly"` and `"go-mod + rust-cargo + javascript-yarn + os-pm combined config"` entries to use file-based os-pm syntax
- [X] T022 [US1] Update other package directive test files (`packages_directive_python_test.go`, `packages_directive_rust_test.go`, `packages_directive_go_mod_test.go`, `packages_directive_lua_test.go`) that reference `PackagesSpec` or `Spec.Packages` assertions — remove or update those assertions
- [X] T023 [US1] Update `managedinput_test.go` in `pkg/sbom/managedinput/` — update SBOM resolver tests to expect that `os-pm` does NOT produce a syft cataloger. Per FR-012, `ToCatalogers()` SHALL skip `os-pm` because delivery-kit parses `pm.lock` directly via its own code. No syft resolver is configured for `os-pm` even though it has a `CatalogerName`
- [X] T024 [US1] Update `packages_test.go` in `pkg/build/stage/` — update Packages stage test to use file-based os-pm syntax and new command generation expectations
- [X] T025 [P] [US1] Add unit test for custom spec/lock paths — test that `spec: custom-pm.yaml` and `lock: custom.lock` produce `pm sync --from custom.lock`
- [X] T026 [P] [US1] Add unit test for env vars with file-based os-pm — test that `env: {HTTP_PROXY: "http://proxy.example.com:8080"}` passes the env var inline before `pm sync --from pm.lock`
- [X] T027 [P] [US1] Add unit test for workdir rejection — test that setting `workdir: /app` with `type: os-pm` produces a validation error
- [X] T028 [P] [US1] Add unit test for inline spec list rejection — test that `spec: [curl, jq]` with `type: os-pm` produces an unmarshal/validation error

**Checkpoint**: At this point, User Story 1 should be fully functional — config parsing, command generation, build-phase lock path propagation, PM BOMPatcher enrichment, and delivery-kit's own pm.lock parsing all work correctly. All unit tests pass.

---

## Phase 4: User Story 2 — stageDependencies triggers packages stage on spec/lock changes (Priority: P1)

**Goal**: When `git.stageDependencies.packages` tracks `pm.yaml` and `pm.lock`, changes to these files invalidate the packages stage and trigger re-execution.

**Independent Test**: The `stage_deps_file` e2e test validates that changes to `pm.yaml` or `pm.lock` cause the packages stage checksum to change (cache miss on subsequent build).

- [X] T029 [P] [US2] Migrate `stage_deps_file` e2e fixtures (`state0`, `state1`) in `test/e2e/sbom/_fixtures/stage_deps_file/` — replace inline `spec: [jq==1.8.1]` with `pm.yaml` + `pm.lock` files at repo root for each state. Update `git.stageDependencies.packages` to track `pm.yaml` and `pm.lock` instead of `versions.txt`
- [X] T030 [US2] Update `stage_dependencies_test.go` in `test/e2e/sbom/` — update test assertions from inline `pm install` command expectations to `pm sync --from pm.lock` expectations. Validate that changes to `pm.yaml` or `pm.lock` trigger packages stage re-execution
- [X] T031 [US2] Migrate `stage_deps` e2e fixtures (`state0`, `state1`, `state2`) in `test/e2e/sbom/_fixtures/stage_deps/` — replace inline `spec: [jq==1.8.1]` with `pm.yaml` + `pm.lock` files. Generate `pm.lock` via `pm lock --from=pm.yaml`

**Checkpoint**: At this point, User Story 2 should be e2e-verifiable — stage dependency changes correctly invalidate packages stage. The `stage_deps_file` e2e test demonstrates SBOM regeneration on spec/lock changes.

---

## Phase 5: User Story 3 — No os-pm packages needed (Priority: P2)

**Goal**: A build without any `os-pm` directive produces no `pm sync` commands, no lock path propagation, and skips os-pm SBOM processing entirely.

**Independent Test**: A build without `os-pm` in `packages` generates no `pm sync` command, `OSPMLockPath()` returns empty string, and the PM BOMPatcher is not invoked.

- [X] T032 [P] [US3] Add unit test for no os-pm → no pm sync in `pkg/config/packages_commands_test.go` — test that `GeneratePackagesCommands()` returns empty slice when no `os-pm` directive is present (even if other package types exist)
- [X] T033 [P] [US3] Add unit test for `OSPMLockPath()` returning empty string — test that `StapelImageBase.OSPMLockPath()` returns `""` when no `os-pm` packages are configured
- [X] T034 [P] [US3] Add unit test for build-phase without os-pm — test that `convergeImageSbom()` passes empty `osPmLockPath` when no os-pm packages exist, and `ConvergeWithMerge()` skips PM BOMPatcher creation
- [X] T035 [P] [US3] Add unit test for non-os-pm types skipping os-pm in `pkg/sbom/managedinput/managedinput_test.go` — test that `ToCatalogers()` does not include `"os-pm-lock-cataloger"` when no `os-pm` packages are configured

**Checkpoint**: All user stories should now be independently functional — the system handles both the presence and absence of `os-pm` packages correctly.

---

## Phase 6: Dead Code Cleanup

**Purpose**: Remove code that is no longer needed after the migration to file-based syntax. Preserve parser functions that are reused for `pm.lock` from build context.

- [X] T036 [P] Remove `collectInstalledPackets()` from `pkg/sbom/packages/os_pm/collect.go` — this function reads runtime index from inside the built image (`/var/lib/pm/index.json`) and is no longer needed (per FR-010b, FR-017)
- [X] T037 [P] Remove `ContainerFactoryVersionIndexFile` constant from `pkg/config/packages_commands.go` — this constant references the runtime index file path that is no longer written
- [X] T038 [P] Update `CollectBOM()` in `pkg/sbom/packages/os_pm/collect.go` — remove the `collectInstalledPackets()` call, keep `readContainerFactoryVersion()` for SBOM purl qualifier (per FR-002, FR-010b, reused by PM BOMPatcher)
- [X] T039 Remove `HasOSPMPackages()` from `pkg/config/stapel_image_base.go` — after migrating all callers to `OSPMLockPath()`, remove the old boolean method
- [X] T040 [P] Clean up `os_pm_test.go`, `suite_test.go`, and `testdata/` in `pkg/sbom/packages/os_pm/` — remove tests and test fixtures for the dead `collectInstalledPackets()` function. Keep tests for `readContainerFactoryVersion()`, `ParsePmLock()`, and `collectPacketsFromLock()` which are reused for `pm.lock`

---

## Phase 7: E2E Fixture Migration — All Fixtures to File-Based Syntax

**Purpose**: Migrate all remaining e2e test fixtures (beyond stage_deps and stage_deps_file already handled in US2) from inline `os-pm` syntax to file-based `pm.yaml`/`pm.lock` syntax.

- [X] T041 [P] Migrate `inject/ospm_basic` fixture in `test/e2e/sbom/_fixtures/inject/ospm_basic/` — replace inline `spec: [curl==8.12.1]` with `pm.yaml` + `pm.lock` files
- [X] T042 [P] Migrate `inject/ospm_gost_override` fixture in `test/e2e/sbom/_fixtures/inject/ospm_gost_override/` — same migration
- [X] T043 [P] Migrate `inject/ospm_scratch_secrets` fixture in `test/e2e/sbom/_fixtures/inject/ospm_scratch_secrets/` — same migration
- [X] T044 [P] Migrate `type_change/state0` fixture in `test/e2e/sbom/_fixtures/type_change/state0/` — replace inline `spec: [jq==1.8.1]` with `pm.yaml` + `pm.lock` files
- [X] T045 [P] Migrate `packages_merge/base_with_child` fixture in `test/e2e/sbom/_fixtures/packages_merge/base_with_child/` — replace inline `spec:` with `pm.yaml` + `pm.lock`
- [X] T046 [P] Migrate `packages_merge/parent_propagation` fixture in `test/e2e/sbom/_fixtures/packages_merge/parent_propagation/` — same migration
- [X] T047 [P] Migrate `lifecycle/multi_image` fixture in `test/e2e/sbom/_fixtures/lifecycle/multi_image/` — replace inline `spec:` with `pm.yaml` + `pm.lock`
- [X] T048 [P] Migrate `purl_resolver_errors` fixture in `test/e2e/sbom/_fixtures/purl_resolver_errors/` — replace inline `spec:` with `pm.yaml` + `pm.lock`
- [X] T049 [P] Migrate `negative/broken_pm` fixture in `test/e2e/sbom/_fixtures/negative/broken_pm/` — replace inline `spec:` with `pm.yaml` + `pm.lock`
- [X] T050 [P] Migrate `negative/no_pm_binary` fixture in `test/e2e/sbom/_fixtures/negative/no_pm_binary/` — replace inline `spec:` with `pm.yaml` + `pm.lock`
- [X] T051 [P] Migrate `regressions/manifest_annotation` fixture in `test/e2e/sbom/_fixtures/regressions/manifest_annotation/` — replace inline `spec:` with `pm.yaml` + `pm.lock`
- [X] T052 Generate `pm.lock` for each migrated e2e fixture by running `pm lock --from=pm.yaml` in each fixture directory
- [X] T053 [P] Update `packages_test.go` in `test/e2e/sbom/` — update `pm install` command assertions to `pm sync --from pm.lock` expectations
- [X] T054 [P] Update `gost_test.go` in `test/e2e/sbom/` — update os-pm GOST override test expectations for file-based syntax
- [X] T055 [P] Update `lifecycle_test.go` in `test/e2e/sbom/` — update lifecycle test expectations for file-based syntax and command generation

---

## Phase 8: Polish & Cross-Cutting Concerns

**Purpose**: Final validation, formatting, and ensuring all tests pass.

- [X] T056 [P] Run `task format` to format all changed Go files
- [X] T057 Run `task build` to verify the project compiles
- [X] T058 Run `task test:unit` with `paths="./pkg/config/..."` to validate all config unit tests pass
- [X] T059 Run `task test:unit` with `paths="./pkg/sbom/..."` to validate SBOM tests pass (managedinput + os_pm package)
- [X] T060 Run `task test:unit` with `paths="./pkg/build/..."` to validate build phase tests pass
- [X] T061 [P] Run `task lint:golangci-lint` to verify no linter violations were introduced

---

## Dependencies & Execution Order

### Phase Dependencies

- **Setup (Phase 1)**: No dependencies — can start immediately
- **Foundational (Phase 2)**: Depends on Setup completion — BLOCKS all user stories
- **User Story 1 (Phase 3)**: Depends on Foundational (Phase 2) completion
- **User Story 2 (Phase 4)**: Depends on Foundational (Phase 2) completion. Partially overlaps with Phase 7 (e2e fixture migration)
- **User Story 3 (Phase 5)**: Depends on Foundational (Phase 2) completion
- **Dead Code Cleanup (Phase 6)**: Depends on US1 completion (must verify file-based syntax works before removing old code paths)
- **E2E Fixture Migration (Phase 7)**: Depends on Foundational completion. US2 (Phase 4) must be complete before running overlapping e2e tests
- **Polish (Phase 8)**: Depends on all desired user stories and cleanup being complete

### User Story Dependencies

- **User Story 1 (P1)**: Can start after Foundational (Phase 2) — No dependencies on other stories
- **User Story 2 (P1)**: Can start after Foundational (Phase 2) — May share e2e fixture migration tasks with Phase 7
- **User Story 3 (P2)**: Can start after Foundational (Phase 2) — Independent of US1 and US2

### Within Each User Story

- Config model changes before commands
- Build-phase signature changes before BOMPatcher
- Tests before-and-after implementation
- Story complete before moving to next priority

### Parallel Opportunities

- All Foundational tasks marked [P] (T006, T007) can run in parallel
- All US1 [P] tasks (T017, T018, T025, T026, T027, T028) can run in parallel (different files or non-overlapping source files)
- All US2 [P] tasks can run in parallel
- All US3 [P] tasks can run in parallel
- All dead code cleanup [P] tasks (T036, T037, T038, T040) can run in parallel
- All e2e fixture migration [P] tasks can run in parallel (different fixture directories)
- All e2e Go test file updates [P] tasks can run in parallel
- All Polish [P] tasks can run in parallel

---

## Parallel Example: User Story 1

```bash
# Launch all parallelizable US1 tasks together:
Task: "Wire up pm.lock parser in pkg/sbom/packages/os_pm/collect.go"
Task: "Ensure managedinput skips os-pm in pkg/sbom/managedinput/managedinput.go"
Task: "Write custom spec/lock test in pkg/config/raw_packages_directive_test.go"
Task: "Write env var test in pkg/config/packages_commands_test.go"
Task: "Write workdir rejection test in pkg/config/raw_packages_directive_test.go"
Task: "Write inline spec rejection test in pkg/config/raw_packages_directive_test.go"
```

---

## Implementation Strategy

### MVP First (User Story 1 Only)

1. Complete Phase 1: Setup
2. Complete Phase 2: Foundational (CRITICAL — blocks all stories)
3. Complete Phase 3: User Story 1
4. **STOP and VALIDATE**: `task test:unit paths="./pkg/config/..."`, `task test:unit paths="./pkg/sbom/..."`, and `task test:unit paths="./pkg/build/..."` pass
5. Deploy/demo if ready

### Incremental Delivery

1. Complete Setup + Foundational → Foundation ready (core model changes, validation, builder interface)
2. Add User Story 1 → Test independently (`task test:unit paths="./pkg/config/..."`, `task test:unit paths="./pkg/build/..."`) → MVP
3. Add User Story 2 → Test independently (stage_deps_file e2e test) → Deploy/Demo
4. Add User Story 3 → Test independently (no-os-pm tests) → Deploy/Demo
5. Clean up dead code → Phase 6
6. Migrate remaining e2e fixtures → Phase 7
7. Final polish → Phase 8

### Parallel Team Strategy

With multiple developers:

1. Team completes Setup + Foundational together
2. Once Foundational is done:
   - Developer A: User Story 1 (config + build phase + BOMPatcher) + Dead Code Cleanup
   - Developer B: User Story 2 + E2E fixture migration (stage_deps, stage_deps_file)
   - Developer C: User Story 3 + E2E fixture migration (remaining 11 fixtures + Go test updates)
3. Stories complete and integrate independently

---

## Notes

- [P] tasks = different files, no dependencies
- [Story] label maps task to specific user story for traceability
- Each user story should be independently completable and testable
- The `Buildah` and container backend changes cannot be compiled on macOS — Buildah changes are linux/amd64 only. All config, SBOM, and build-phase changes compile and test on any platform (the build-phase code is in platform-independent Go files)
- The `pm.lock` file for e2e fixtures is generated by `pm lock --from=pm.yaml` — do NOT hand-write pm.lock
- The PM BOMPatcher reuses `readContainerFactoryVersion()` from `pkg/sbom/packages/os_pm/collect.go` (preserved, not removed)
- FR-012: delivery-kit parses `pm.lock` via its own code — no syft cataloger is created for os-pm. The `CatalogerName` is a metadata label in delivery-kit's own SBOM output
- Commit after each task or logical group
- Stop at any checkpoint to validate story independently
- Avoid: vague tasks, same file conflicts, cross-story dependencies that break independence
