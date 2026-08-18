---

description: "Task list for Inline os-pm Syntax (reverting 015)"
---

# Tasks: Inline os-pm Syntax (reverting 015)

**Input**: Design documents from `specs/017-inline-os-pm-syntax-again/`

**Prerequisites**: `plan.md`, `spec.md`, `research.md`, `data-model.md`, `contracts/`, `quickstart.md`

**Tests**: Tests are required by the feature specification and constitution. Use Ginkgo + Gomega and keep tests co-located with the code under test.

**Organization**: Tasks are grouped by user story. US1 and US2 are P1; US3 is P2.

## Checklist format

Every task uses `- [ ] Txxx`, includes an exact project-relative file path, and has a story label only in user-story phases. `[P]` means the task can run in parallel without depending on incomplete work in another task.

## Build & Test Commands

- Format: `task format`
- Build: `task build`
- Unit tests: `task test:unit paths="./pkg/..."`
- E2E tests: `task test:e2e paths="./test/e2e/sbom/..." labelFilter="..."`
- Lint: `task lint`
- Never use raw `go build`, `go test`, `go fmt`, `go vet`, or `golangci-lint`.

---

## Phase 1: Setup (Shared Infrastructure)

**Purpose**: Establish the implementation inventory and preserve the design constraints before editing code.

- [ ] T001 Verify the feature artifacts in `specs/017-inline-os-pm-syntax-again/plan.md`, `specs/017-inline-os-pm-syntax-again/spec.md`, `specs/017-inline-os-pm-syntax-again/research.md`, `specs/017-inline-os-pm-syntax-again/data-model.md`, `specs/017-inline-os-pm-syntax-again/contracts/`, and `specs/017-inline-os-pm-syntax-again/quickstart.md`.
- [ ] T002 [P] Inventory file-based os-pm references, lock-path APIs, and PM command generation in `pkg/config/`, `pkg/build/`, `pkg/sbom/`, `Taskfile.dist.yaml`, `AGENTS.md`, and `test/e2e/sbom/`.
- [ ] T003 [P] Inventory SBOM checksum inputs, cache annotations, and image-set error aggregation in `pkg/build/sbom_step.go`, `pkg/build/sbom_step_checksum_test.go`, `pkg/build/sbom_step_test.go`, and `pkg/build/build_phase.go`.
- [ ] T004 [P] Inspect current package dependency direction and identify all consumers of PM metadata before introducing `pkg/packages_metadata/os_pm.go`.

**Checkpoint**: All affected APIs, fixtures, cache behavior, and dependency constraints are known before implementation.

---

## Phase 2: Foundational (Blocking Prerequisites)

**Purpose**: Restore the shared configuration model and introduce dependency-neutral PM metadata before user-story work.

- [ ] T005 [P] Create dependency-free PM metadata constants in `pkg/packages_metadata/os_pm.go`: `ContainerFactoryIndexPath`, `ContainerFactoryVersionPath`, and `CatalogerName`.
- [ ] T006 [P] Add a package-level dependency test or static dependency check in `pkg/packages_metadata/os_pm_test.go` proving `pkg/packages_metadata/os_pm.go` imports neither `pkg/config`, SBOM collectors, nor container backends.
- [ ] T007 Restore `PackagesSpec{Packages []string}` and update the `PackageEcosystem.InstallCmd` callback signature in `pkg/config/packages_directive.go`.
- [ ] T008 Update all non-os-pm ecosystem callbacks to the restored callback signature without changing their file-based behavior in `pkg/config/packages_directive.go`.
- [ ] T009 Configure the os-pm ecosystem entry with empty default spec/lock files and `packages_metadata.CatalogerName` in `pkg/config/packages_directive.go`.
- [ ] T010 Remove os-pm file-based resolution from `fillFileBasedSpec` and restore inline list conversion in `pkg/config/raw_packages_directive.go`.
- [ ] T011 Restore `HasOSPMPackages()` and remove `OSPMLockPath()` and `OSPMSpecPath()` in `pkg/config/stapel_image_base.go`.
- [ ] T012 Update callers of the removed lock/spec path methods to use `HasOSPMPackages()` in `pkg/build/build_phase.go` and `pkg/config/raw_stapel_image.go`.
- [ ] T013 [P] Update foundational parsing and ecosystem tests for inline `PackagesSpec`, neutral metadata, empty defaults, and the `HasOSPMPackages()` API in `pkg/config/raw_packages_directive_test.go`, `pkg/config/packages_directive_test.go`, and `pkg/config/stapel_image_base_test.go`.
- [ ] T014 Run foundational tests with `task test:unit paths="./pkg/config/..."` and `task test:unit paths="./pkg/sbom/managedinput/..."`.

**Checkpoint**: Inline os-pm data, neutral metadata, and boolean enablement are available to all stories without a lock-file path.

---

## Phase 3: User Story 1 — Declare OS packages inline, multiple sections (Priority: P1) 🎯 MVP

**Goal**: Accept only non-empty inline os-pm package lists, support multiple sections with independent environment values, and generate one correctly exported `pm install` command per section.

**Independent Test**: Config and stage tests accept `spec: [curl, jq]`, reject string/file specs, empty lists, and `workdir`; multiple sections generate independent commands; every required and user env variable is on the same shell invocation as `pm install`, with no `; pm install` form.

### Tests for User Story 1

- [ ] T015 [P] [US1] Add inline parsing cases for accepted lists, rejected string paths, empty lists, `workdir` rejection, multiple sections, and per-section env preservation in `pkg/config/raw_packages_directive_test.go`.
- [ ] T016 [P] [US1] Update mixed package directive fixtures to use inline os-pm lists and verify the neutral cataloger registration in `pkg/config/packages_directive_javascript_test.go` and `pkg/config/packages_directive_test.go`.
- [ ] T017 [P] [US1] Add exact command-generation assertions for package arguments, version constraints, preamble, multiple sections, required env variables, user env variables, same-command env prefixes, and absence of `; pm install` in `pkg/config/packages_commands_test.go`.
- [ ] T018 [P] [US1] Update positive and negative `HasOSPMPackages()` cases in `pkg/config/stapel_image_base_test.go`.
- [ ] T019 [P] [US1] Update stage integration expectations for inline os-pm commands and multiple sections in `pkg/build/stage/packages_test.go`.

### Implementation for User Story 1

- [ ] T020 [US1] Implement os-pm list conversion and validation for non-empty lists, rejected string paths, and rejected `workdir` in `pkg/config/raw_packages_directive.go`.
- [ ] T021 [US1] Implement `formatInstallCommand` with `pm install <packages>`, the version-file preamble, and all required/user env assignments as prefixes on the same command invocation in `pkg/config/packages_commands.go`.
- [ ] T022 [US1] Reuse `packages_metadata.ContainerFactoryVersionPath` and other shared PM metadata from command generation without redeclaring path literals in `pkg/config/packages_commands.go`.
- [ ] T023 [US1] Wire inline package lists, the neutral cataloger name, and the updated callback through the os-pm ecosystem in `pkg/config/packages_directive.go`.
- [ ] T024 [US1] Generate one install command for each os-pm section through stage/build configuration wiring in `pkg/build/stage/packages.go` and `pkg/config/raw_stapel_image.go`.
- [ ] T025 [US1] Run the independent US1 tests with `task test:unit paths="./pkg/config/..."` and `task test:unit paths="./pkg/build/stage/..."`.

**Checkpoint**: Inline os-pm configuration produces valid independent commands, and all legacy file-based forms fail at parse or validation time.

---

## Phase 4: User Story 2 — SBOM from final state in image (Priority: P1)

**Goal**: Build the os-pm SBOM from the final `/var/lib/pm/index.json`, merge it before external-reference enrichment, and preserve hierarchical resolver error aggregation.

**Independent Test**: Unit tests prove runtime components reach the PURL patcher and resolver errors propagate; checksum tests use distinct inputs; the resolver e2e test proves mixed image outcomes and fresh SBOM generation.

### Tests for User Story 2

- [ ] T026 [P] [US2] Add `CollectBOM` coverage for index reads, empty/missing index behavior, malformed JSON, package conversion, version-file success, expected missing version file, and unexpected version-read errors in `pkg/sbom/packages/os_pm/collect_test.go`.
- [ ] T027 [P] [US2] Add a package-level regression proving runtime components are integrated before `externalref.ExternalRefPatcher`, `ErrExternalRefEnrich` propagates, and host `PACKAGES_VERSION` is not used in `pkg/sbom/packages/os_pm/collect_test.go` or a co-located integration test.
- [ ] T028 [P] [US2] Replace the identical-argument checksum assertion with a meaningful test using distinct inputs and verify the generic checksum excludes a separate os-pm enablement flag in `pkg/build/sbom_step_checksum_test.go` and `pkg/build/sbom_step_test.go`.
- [ ] T029 [P] [US2] Verify os-pm remains excluded from Syft resolver derivation in `pkg/sbom/managedinput/managedinput_test.go`.
- [ ] T030 [P] [US2] Update stage/build tests for boolean os-pm enablement and runtime BOM collection in `pkg/build/stage/packages_test.go`.

### Implementation for User Story 2

- [ ] T031 [P] [US2] Reuse `packages_metadata.ContainerFactoryIndexPath`, `packages_metadata.ContainerFactoryVersionPath`, and `packages_metadata.CatalogerName` from the os-pm collector in `pkg/sbom/packages/os_pm/collect.go`.
- [ ] T032 [P] [US2] Implement explicit expected-missing-file versus unexpected-read-error handling for the container-factory version in `pkg/sbom/packages/os_pm/collect.go`; unexpected errors must be logged with context or returned, never silently discarded.
- [ ] T033 [P] [US2] Remove `PMBOMPatcher` and its tests from `pkg/sbom/packages/os_pm/pm_bom_patcher.go` and `pkg/sbom/packages/os_pm/pm_bom_patcher_test.go`.
- [ ] T034 [US2] Replace lock/spec path propagation with `hasOsPmPackages` in `pkg/build/build_phase.go` and pass the required os-pm state into the SBOM pipeline.
- [ ] T035 [US2] Move runtime-index collection and component/dependency integration behind the os-pm package operation, invoking it before `externalref.ExternalRefPatcher` without duplicate merge logic in `pkg/build/sbom_step.go` and `pkg/sbom/packages/os_pm/collect.go`.
- [ ] T036 [US2] Preserve resolver error wrapping, component details, successful-image continuation, and hierarchical aggregation in `pkg/build/build_phase.go` and `pkg/sbom/externalref/patcher.go`.
- [ ] T037 [US2] Remove the os-pm-specific checksum input and `os-pm-enabled` checksum part while preserving generic scan/merge/signer/platform inputs in `pkg/build/sbom_step.go`.
- [ ] T038 [US2] Run focused US2 unit tests with `task test:unit paths="./pkg/sbom/..." -- -focus="os-pm|external|SBOM"` and `task test:unit paths="./pkg/build/..."`.

### PURL Resolver E2E Regression

- [ ] T039 [P] [US2] Ensure every expected failing component, especially `openssl`, is guaranteed by the fixture declaration or base image in `test/e2e/sbom/_fixtures/purl_resolver_errors/Dockerfile.builder-base` and `test/e2e/sbom/_fixtures/purl_resolver_errors/werf.yaml`.
- [ ] T040 [US2] Update the mixed-outcome resolver test to assert only guaranteed component PURLs and preserve image-level hierarchical aggregation in `test/e2e/sbom/purl_resolver_errors_test.go`.
- [ ] T041 [US2] Run the focused resolver regression with `task test:e2e paths="./test/e2e/sbom/..." labelFilter="purl-resolver-errors"` and confirm it exercises fresh SBOM generation rather than a cache hit.

**Checkpoint**: Runtime os-pm components participate in PURL resolution, resolver failures aggregate correctly, and cache behavior cannot hide the regression.

---

## Phase 5: User Story 3 — No os-pm packages needed (Priority: P2)

**Goal**: Skip os-pm command generation and runtime-index collection when no os-pm packages are configured.

**Independent Test**: Config and build tests prove `HasOSPMPackages()` is false for absent/non-os-pm directives, no PM command is generated, and `CollectBOM` is not invoked.

### Tests for User Story 3

- [ ] T042 [P] [US3] Add no-package and non-os-pm-only cases in `pkg/config/stapel_image_base_test.go`.
- [ ] T043 [P] [US3] Add managed-input coverage for the no-os-pm path in `pkg/sbom/managedinput/managedinput_test.go`.
- [ ] T044 [P] [US3] Add build/SBOM coverage proving `CollectBOM` is not called when os-pm is disabled in `pkg/build/sbom_step_test.go`.

### Implementation for User Story 3

- [ ] T045 [US3] Ensure `HasOSPMPackages()` gates command generation and SBOM collection without changing other ecosystems in `pkg/config/stapel_image_base.go`, `pkg/config/packages_commands.go`, and `pkg/build/sbom_step.go`.
- [ ] T046 [US3] Run the independent US3 tests with `task test:unit paths="./pkg/config/..."` and `task test:unit paths="./pkg/sbom/..." -- -focus="os-pm"`.

**Checkpoint**: Projects without os-pm packages retain existing behavior and do not perform unnecessary runtime-index SBOM processing.

---

## Phase 6: Polish & Cross-Cutting Concerns

**Purpose**: Remove obsolete lock workflow, migrate fixtures, synchronize documentation, and execute repository quality gates.

- [ ] T047 [P] Migrate all os-pm SBOM fixtures under `test/e2e/sbom/_fixtures/` from `pm.yaml`/`pm.lock` to inline `spec` lists and delete obsolete fixture files.
- [ ] T048 [P] Remove the obsolete `pm:lock` task from `Taskfile.dist.yaml` and its stale lock-artifact instructions from `AGENTS.md`.
- [ ] T049 [P] Verify no `PMBOMPatcher` or os-pm build-context lock source remains in `Taskfile.dist.yaml`, `AGENTS.md`, `pkg/config/`, `pkg/build/`, `pkg/sbom/`, and `test/e2e/sbom/`.
- [ ] T050 [P] Verify `pkg/config/` consumes PM metadata only through `pkg/packages_metadata/` and that `pkg/packages_metadata/os_pm.go` remains dependency-neutral.
- [ ] T051 [P] Run the package-focused e2e suite with `task test:e2e paths="./test/e2e/sbom/..." labelFilter="packages"`.
- [ ] T052 Run `task format` for changed Go packages under `pkg/config/`, `pkg/build/`, `pkg/sbom/`, and `pkg/packages_metadata/`.
- [ ] T053 Run `task build` and resolve implementation-caused compilation failures in `pkg/config/`, `pkg/build/`, `pkg/sbom/`, and `pkg/packages_metadata/`.
- [ ] T054 Run `task lint` and resolve implementation-caused diagnostics in `pkg/config/`, `pkg/build/`, `pkg/sbom/`, and `pkg/packages_metadata/`.
- [ ] T055 Run `task test:unit` and record unrelated pre-existing failures without masking implementation failures in `pkg/config/`, `pkg/build/`, `pkg/sbom/`, and `pkg/packages_metadata/`.
- [ ] T056 Run the full relevant SBOM e2e suite with `task test:e2e paths="./test/e2e/sbom/..." labelFilter="sbom"`.
- [ ] T057 Validate changed authored artifacts with `git diff --check -- specs/017-inline-os-pm-syntax-again/`.

---

## Dependencies & Execution Order

### Phase Dependencies

- Setup (Phase 1) has no implementation dependency.
- Foundational (Phase 2) depends on Setup and blocks all user stories.
- US1 depends on Foundational and delivers the MVP config/command flow.
- US2 depends on Foundational plus the `HasOSPMPackages()`/SBOM wiring; its e2e regression depends on the collector and pipeline implementation.
- US3 depends on Foundational and can proceed in parallel with US1/US2 where files do not overlap.
- Polish (Phase 6) depends on completed US1, US2, and US3; T052–T057 are sequential quality gates after implementation tasks.

### User Story Dependencies

- US1 (P1): Foundational only.
- US2 (P1): Foundational; shares build/config wiring with US1, so integrate after the shared model is stable.
- US3 (P2): Foundational; validates the no-os-pm boundary independently.

### Parallel Opportunities

- T002–T004 can run in parallel.
- T005–T006 and T007–T013 can run in parallel when files do not overlap; T014 follows foundational edits.
- T015–T019 can run in parallel; implementation T020–T024 follows the relevant test updates.
- T026–T030 can run in parallel; T031–T033 can run in parallel before T034–T037.
- T039 and T040 can run in parallel if fixture and test ownership are separated.
- T042–T044 can run in parallel.
- T047–T051 can run in parallel after story implementations stabilize.

## Parallel Examples

### User Story 1

```text
T015: pkg/config/raw_packages_directive_test.go
T016: pkg/config/packages_directive_javascript_test.go and pkg/config/packages_directive_test.go
T017: pkg/config/packages_commands_test.go
T018: pkg/config/stapel_image_base_test.go
T019: pkg/build/stage/packages_test.go
```

### User Story 2

```text
T026: pkg/sbom/packages/os_pm/collect_test.go
T027: pkg/sbom/packages/os_pm/collect_test.go or co-located integration test
T028: pkg/build/sbom_step_checksum_test.go and pkg/build/sbom_step_test.go
T029: pkg/sbom/managedinput/managedinput_test.go
T039: test/e2e/sbom/_fixtures/purl_resolver_errors/
```

### User Story 3

```text
T042: pkg/config/stapel_image_base_test.go
T043: pkg/sbom/managedinput/managedinput_test.go
T044: pkg/build/sbom_step_test.go
```

## Implementation Strategy

### MVP First

1. Complete Phase 1 and Phase 2.
2. Complete US1: inline parsing, multiple sections, and correctly exported `pm install` commands.
3. Run the US1 independent tests.
4. Stop for review/demo if the inline os-pm MVP is sufficient.

### Incremental Delivery

1. Deliver US1 as the inline syntax MVP.
2. Deliver US2 with runtime-index SBOM collection, final-BOM enrichment, meaningful checksum coverage, and resolver aggregation.
3. Deliver US3 no-os-pm behavior.
4. Complete fixture migration, lock-workflow cleanup, documentation synchronization, and full quality gates.

### Final Validation Sequence

After Go changes, run in order: `task format`, `task build`, `task lint`, `task test:unit`, then the targeted and full relevant e2e commands.

## Notes

- Do not add dependencies without explicit review.
- Use `task mock:generate` if generated mocks require changes; never edit generated mocks manually.
- Do not modify `CHANGELOG.md` or generated release files.
- The PURL resolver fix is a pipeline-order change in `pkg/build/sbom_step.go`, not a resolver-service change.
- Before implementation, reconcile the spec wording around `containerFactoryVersion` fallback with the plan decision: the collector must not read a host environment variable, and unexpected version-file errors must not be silently swallowed.
