---

description: "Task list for Inline os-pm Syntax (reverting 015)"
---

# Tasks: Inline os-pm Syntax (reverting 015)

**Input**: Design documents from `specs/017-inline-os-pm-syntax-again/`

**Prerequisites**: `plan.md`, `spec.md`, `research.md`, `data-model.md`, `contracts/`, `quickstart.md`

**Tests**: Tests are required by the feature specification and the project constitution. Use Ginkgo + Gomega and keep tests co-located with the code under test.

**Organization**: Tasks are grouped by user story. US1 and US2 are P1; US3 is P2.

## Format: `[ID] [P?] [Story?] Description`

- **[P]**: Tasks touch different files and have no dependency on incomplete work.
- **[Story]**: User-story tasks use `[US1]`, `[US2]`, or `[US3]`.
- Every task includes an exact project-relative file path.

## Path Conventions

- **Business logic**: `pkg/<domain>/`
- **Unit tests**: co-located `*_test.go` files
- **E2E tests**: `test/e2e/sbom/`
- **Fixtures**: `test/e2e/sbom/_fixtures/`

## Build & Test Commands

- **Format**: `task format`
- **Build**: `task build`
- **Unit tests**: `task test:unit paths="./pkg/..."`
- **E2E tests**: `task test:e2e paths="./test/e2e/sbom/..." labelFilter="..."`
- **Lint**: `task lint`
- Do not use raw `go build`, `go test`, `go fmt`, `go vet`, or `golangci-lint`.

---

## Phase 1: Setup (Shared Infrastructure)

**Purpose**: Confirm the existing feature workspace and preserve the design decisions before implementation.

- [X] T001 Verify the implementation branch and feature artifacts in `specs/017-inline-os-pm-syntax-again/plan.md`, `specs/017-inline-os-pm-syntax-again/spec.md`, `specs/017-inline-os-pm-syntax-again/research.md`, `specs/017-inline-os-pm-syntax-again/data-model.md`, `specs/017-inline-os-pm-syntax-again/contracts/`, and `specs/017-inline-os-pm-syntax-again/quickstart.md`
- [X] T002 [P] Inventory all current os-pm file-based references in `pkg/config/`, `pkg/build/`, `pkg/sbom/`, and `test/e2e/sbom/` before editing implementation files
- [X] T003 [P] Inventory existing SBOM cache checksum and annotation behavior in `pkg/build/sbom_step.go` and related tests before changing the SBOM pipeline

---

## Phase 2: Foundational (Blocking Prerequisites)

**Purpose**: Restore the shared configuration and ecosystem model that all user stories use.

**Critical**: Complete this phase before implementing the user stories.

- [X] T004 [P] Restore `PackagesSpec{Packages []string}` and the os-pm cataloger constant in `pkg/config/packages_directive.go`
- [X] T005 [P] Update `PackageEcosystem.InstallCmd` and all ecosystem callback implementations to accept `FileBasedSpec`, inline package arguments, and environment variables in `pkg/config/packages_directive.go`
- [X] T006 [P] Restore the os-pm ecosystem metadata with empty default spec/lock files, runtime-index cataloger name, and inline install command behavior in `pkg/config/packages_directive.go`
- [X] T007 [P] Remove os-pm file-based resolution from `fillFileBasedSpec` and restore list conversion for os-pm in `pkg/config/raw_packages_directive.go`
- [X] T008 [P] Restore `HasOSPMPackages()` and remove `OSPMLockPath()` and `OSPMSpecPath()` from `pkg/config/stapel_image_base.go`
- [X] T009 Update callers of removed lock/spec path methods to use `HasOSPMPackages()` in `pkg/build/build_phase.go` and `pkg/config/raw_stapel_image.go`
- [X] T010 Verify the foundational configuration changes compile with `task test:unit paths="./pkg/config/..."`

**Checkpoint**: Inline os-pm data can be represented without a lock-file path, and all user stories can consume the shared model.

---

## Phase 3: User Story 1 — Declare OS packages inline, multiple sections (Priority: P1) 🎯 MVP

**Goal**: Accept only inline non-empty os-pm package lists, support multiple sections with independent env values, and generate one `pm install` command per section.

**Independent Test**: `task test:unit paths="./pkg/config/..." -- -focus="os-pm"` passes with inline lists, rejects string/file specs, rejects empty specs and workdir, and verifies per-section environment prefixes and commands.

### Tests for User Story 1

- [X] T011 [P] [US1] Update inline spec parsing cases, including acceptance of `spec: [curl, jq]`, rejection of `spec: "pm.yaml"`, empty-list rejection, workdir rejection, and env preservation in `pkg/config/raw_packages_directive_test.go`
- [X] T012 [P] [US1] Update mixed package directive fixtures to use inline os-pm lists in `pkg/config/packages_directive_javascript_test.go`
- [X] T013 [P] [US1] Add command-generation coverage for one package section, multiple sections, version constraints, preamble, and per-section environment prefixes in `pkg/config/packages_commands_test.go`
- [X] T014 [P] [US1] Update `HasOSPMPackages()` positive and negative cases in `pkg/config/stapel_image_base_test.go`
- [X] T015 [P] [US1] Update stage package integration expectations for inline os-pm commands in `pkg/build/stage/packages_test.go`

### Implementation for User Story 1

- [X] T016 [US1] Implement os-pm list conversion and type-specific validation for non-empty list, rejected string path, and rejected workdir in `pkg/config/raw_packages_directive.go`
- [X] T017 [US1] Implement inline `pm install <pkg_1> ... <pkg_N>` command formatting with the version-file preamble and env prefixes in `pkg/config/packages_commands.go`
- [X] T018 [US1] Wire inline package lists and updated `InstallCmd` arguments through command generation in `pkg/config/packages_directive.go`
- [X] T019 [US1] Update stage/build configuration wiring to generate one command for each os-pm section in `pkg/build/stage/packages.go` and `pkg/config/raw_stapel_image.go`
- [X] T020 [US1] Run the US1 independent config and stage tests with `task test:unit paths="./pkg/config/..."` and `task test:unit paths="./pkg/build/stage/..."`

**Checkpoint**: A valid inline os-pm configuration generates the expected independent commands and invalid legacy forms fail at parse/validation time.

---

## Phase 4: User Story 2 — SBOM from final state in image (Priority: P1)

**Goal**: Build the os-pm SBOM from the final `/var/lib/pm/index.json` in the image, enrich every final component through the PURL resolver, and aggregate resolver failures across images.

**Independent Test**: Unit tests prove `CollectBOM` reads and converts runtime state and that the PURL patcher sees components added by `CollectBOM`; the targeted e2e test proves hierarchical mixed-outcome aggregation.

### Tests for User Story 2

- [X] T021 [P] [US2] Add `CollectBOM` tests for image reads, empty/missing index behavior, malformed index errors, package conversion, and container-factory version fallback in `pkg/sbom/packages/os_pm/collect_test.go`
- [ ] T022 [P] [US2] Add a `ConvergeWithMerge` regression test proving a component returned by `CollectBOM` is present when the external-reference patcher runs and that `ErrExternalRefEnrich` is propagated in `pkg/build/sbom_step_test.go`
- [X] T023 [P] [US2] Add SBOM cache regression coverage proving a stale artifact cannot bypass the changed final-BOM/PURL behavior in `pkg/build/sbom_step_test.go`
- [X] T024 [P] [US2] Update os-pm managed-input tests to verify the runtime-index cataloger remains excluded from Syft derivation in `pkg/sbom/managedinput/managedinput_test.go`
- [X] T025 [P] [US2] Update stage/build tests for boolean os-pm enablement and runtime BOM collection in `pkg/build/stage/packages_test.go`

### Implementation for User Story 2

- [X] T026 [P] [US2] Restore `CollectBOM` to read `/var/lib/pm/index.json`, reuse `ParsePmInstalledJSON` and `ConvertToCycloneDX`, and resolve `containerFactoryVersion` from env then image in `pkg/sbom/packages/os_pm/collect.go`
- [X] T027 [P] [US2] Remove the obsolete lock-file SBOM source and its tests from `pkg/sbom/packages/os_pm/pm_bom_patcher.go` and `pkg/sbom/packages/os_pm/pm_bom_patcher_test.go`
- [X] T028 [US2] Replace lock/spec path propagation with `hasOsPmPackages` in `pkg/build/build_phase.go` and pass `osPmEnabled` into the SBOM step
- [X] T029 [US2] Merge `CollectBOM` components and dependencies into `resultBOM` before applying `externalref.ExternalRefPatcher` in `pkg/build/sbom_step.go`
- [X] T030 [US2] Preserve patcher error wrapping and component details so `ErrExternalRefEnrich` reaches `convergeSbomByImagesSets` and successful images remain absent from the aggregate in `pkg/build/build_phase.go` and `pkg/sbom/externalref/patcher.go`
- [X] T031 [US2] Update the SBOM checksum/cache format or invalidation behavior if required by the cache analysis, ensuring cache reuse represents the final BOM and enrichment behavior in `pkg/build/sbom_step.go`
- [X] T032 [US2] Run focused US2 unit tests with `task test:unit paths="./pkg/sbom/..." -- -focus="os-pm|external|SBOM"` and `task test:unit paths="./pkg/build/..."`

### PURL Resolver E2E Regression

- [X] T033 [P] [US2] Verify the purl-resolver fixture declares or inherits every expected failing component, especially `openssl`, in `test/e2e/sbom/_fixtures/purl_resolver_errors/Dockerfile.builder-base` and `test/e2e/sbom/_fixtures/purl_resolver_errors/werf.yaml`
- [X] T034 [US2] Update the mixed-outcome resolver test to assert only guaranteed component PURLs and preserve image-level hierarchical aggregation in `test/e2e/sbom/purl_resolver_errors_test.go`
- [X] T035 [US2] Run the focused resolver regression with `task test:e2e paths="./test/e2e/sbom/..." labelFilter="purl-resolver-errors"` and confirm it performs a fresh SBOM generation rather than a cache hit

**Checkpoint**: Runtime os-pm components participate in PURL resolution, resolver failures are aggregated across images, and cache reuse cannot hide the regression.

---

## Phase 5: User Story 3 — No os-pm packages needed (Priority: P2)

**Goal**: Skip os-pm command generation and runtime-index collection when no os-pm packages are configured.

**Independent Test**: Config and build tests show `HasOSPMPackages()` is false for absent/non-os-pm directives, no pm command is generated, and `CollectBOM` is not invoked for the no-os-pm path.

### Tests for User Story 3

- [X] T036 [P] [US3] Add no-package and non-os-pm-only cases to `pkg/config/stapel_image_base_test.go`
- [X] T037 [P] [US3] Add managed-input coverage for skipping os-pm processing when no os-pm directive is present in `pkg/sbom/managedinput/managedinput_test.go`
- [X] T038 [P] [US3] Add build/SBOM coverage for no `CollectBOM` call when os-pm is disabled in `pkg/build/sbom_step_test.go`

### Implementation for User Story 3

- [X] T039 [US3] Ensure `HasOSPMPackages()` gates command generation and SBOM collection without affecting other package ecosystems in `pkg/config/stapel_image_base.go`, `pkg/config/packages_commands.go`, and `pkg/build/sbom_step.go`
- [X] T040 [US3] Run the US3 independent tests with `task test:unit paths="./pkg/config/..."` and `task test:unit paths="./pkg/sbom/..." -- -focus="os-pm"`

**Checkpoint**: Projects without os-pm packages retain existing behavior and do not perform unnecessary runtime-index SBOM processing.

---

## Phase 6: E2E Fixtures, Polish, and Quality Gates

**Purpose**: Migrate all fixtures, remove obsolete references, and run the repository-required validation sequence.

- [X] T041 [P] Update all os-pm SBOM fixtures under `test/e2e/sbom/_fixtures/` from `pm.yaml`/`pm.lock` to inline `spec` lists and remove obsolete fixture files
- [X] T042 [P] Verify no `PMBOMPatcher` references remain in `pkg/` and no os-pm code path reads `pm.lock` in `pkg/config/`, `pkg/build/`, or `pkg/sbom/`
- [X] T043 [P] Run the package-focused e2e suite with `task test:e2e paths="./test/e2e/sbom/..." labelFilter="packages"`
- [X] T044 Run `task format` for changed Go packages and tests under `pkg/config/`, `pkg/build/`, `pkg/sbom/`, and `test/e2e/sbom/`
- [X] T045 Run `task build` and fix implementation-caused compilation failures in the changed `pkg/config/`, `pkg/build/`, and `pkg/sbom/` code
- [X] T046 Run `task lint` and fix implementation-caused diagnostics in the changed `pkg/config/`, `pkg/build/`, and `pkg/sbom/` code
- [ ] T047 Run `task test:unit` and record any unrelated pre-existing failures without masking implementation failures in `pkg/config/`, `pkg/build/`, and `pkg/sbom/`
- [ ] T048 Run the full relevant SBOM e2e suite under `test/e2e/sbom/` with `task test:e2e paths="./test/e2e/sbom/..." labelFilter="sbom"`
- [X] T049 Validate all changed task/design artifacts with `git diff --check` for `specs/017-inline-os-pm-syntax-again/`

---

## Dependencies & Execution Order

### Phase Dependencies

- **Setup (Phase 1)**: No implementation dependency.
- **Foundational (Phase 2)**: Depends on Setup; blocks all user stories.
- **US1 (Phase 3)**: Depends on Foundational.
- **US2 (Phase 4)**: Depends on Foundational and the shared model; its SBOM tests can begin once the existing `CollectBOM` API is understood, but implementation integrates with the foundational build wiring.
- **US3 (Phase 5)**: Depends on Foundational; can proceed in parallel with US1 and US2 where files do not overlap.
- **Polish (Phase 6)**: Depends on completed US1, US2, and US3.

### User Story Dependencies

- **US1 (P1)**: Foundational only; delivers the MVP command/config flow.
- **US2 (P1)**: Foundational; depends on the resulting `HasOSPMPackages()`/`osPmEnabled` wiring and must be completed before the resolver e2e regression is meaningful.
- **US3 (P2)**: Foundational; validates the no-os-pm boundary independently.

### Within Each User Story

- Write or update tests before implementation and verify the intended failure where practical.
- Implement shared types before consumers.
- Implement `CollectBOM` before changing the SBOM pipeline order.
- Validate the focused story at its checkpoint before moving to cross-cutting polish.

### Parallel Opportunities

- T002 and T003 can run in parallel.
- T004–T008 can run in parallel when edits are in different files; T009 follows their API changes.
- T011–T015 can run in parallel.
- T021–T025 can run in parallel; T026–T027 can run in parallel before T028–T031.
- T033 and T034 can proceed in parallel only if fixture ownership and test ownership are separated.
- US1, US2, and US3 can be assigned to separate developers after Phase 2, subject to file conflicts in shared build/config files.
- T041, T042, and T043 can run in parallel after story implementations stabilize.

---

## Parallel Examples

### User Story 1

```text
T011: pkg/config/raw_packages_directive_test.go
T012: pkg/config/packages_directive_javascript_test.go
T013: pkg/config/packages_commands_test.go
T014: pkg/config/stapel_image_base_test.go
T015: pkg/build/stage/packages_test.go
```

### User Story 2

```text
T021: pkg/sbom/packages/os_pm/collect_test.go
T022: pkg/build/sbom_step_test.go
T023: SBOM cache regression test file identified by T003
T024: pkg/sbom/managedinput/managedinput_test.go
T033: test/e2e/sbom/_fixtures/purl_resolver_errors/
```

### User Story 3

```text
T036: pkg/config/stapel_image_base_test.go
T037: pkg/sbom/managedinput/managedinput_test.go
T038: pkg/build/sbom_step_test.go
```

---

## Implementation Strategy

### MVP First

1. Complete Phase 1 and Phase 2.
2. Complete US1 (inline parsing and command generation).
3. Run `task test:unit paths="./pkg/config/..."` and stage tests.
4. Stop for review/demo if the inline os-pm MVP is sufficient.

### Incremental Delivery

1. Deliver US1 as the inline syntax MVP.
2. Deliver US2 with runtime-index SBOM collection and final-BOM PURL enrichment.
3. Deliver US3 no-os-pm behavior.
4. Complete fixture migration, resolver regression, cache verification, and full quality gates.

### Final Validation Sequence

After Go changes, run in order: `task format`, `task build`, `task lint`, `task test:unit`, then the targeted and full relevant e2e commands from Phase 6.

---

## Notes

- Do not add dependencies without explicit review.
- Use `task mock:generate` if generated mocks require changes; do not edit generated mocks manually.
- Do not modify `CHANGELOG.md` or generated release files.
- The PURL resolver fix is a pipeline-order change in `pkg/build/sbom_step.go`, not a resolver-service change.
