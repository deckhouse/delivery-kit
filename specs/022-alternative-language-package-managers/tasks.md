# Tasks: Alternative Language Package Managers for Packages Directive

**Input**: Design documents from `/specs/022-alternative-language-package-managers/`

**Prerequisites**: `plan.md`, `spec.md`, `research.md`, `data-model.md`, `contracts/`, and `quickstart.md`

**Tests**: Included because the feature plan and constitution explicitly require co-located Ginkgo/Gomega unit tests and four dedicated e2e scenarios.

**Organization**: Tasks are grouped by user story. Shared configuration and command-wrapper work is foundational; each story then adds an independently testable lifecycle increment.

## Phase 1: Setup (Shared Infrastructure)

**Purpose**: Confirm the existing package-directive and e2e fixture surfaces before implementation; no new module or dependency setup is required.

- [X] T001 Review the existing package directive, ecosystem registry, command-generation, stage checksum, and SBOM paths in `pkg/config/`, `pkg/build/stage/`, and `test/e2e/sbom/` against `specs/022-alternative-language-package-managers/contracts/`
- [X] T002 [P] Identify the current Yarn, pnpm, uv, and Poetry fixture inputs and assertions in `test/e2e/sbom/_fixtures/inject/` and `test/e2e/sbom/*_test.go` without changing generated or release-managed files
- [X] T003 [P] Confirm the package-directive documentation sections to update in `docs/pages_en/usage/build/stapel/instructions.md` and `docs/pages_ru/usage/build/stapel/instructions.md`

---

## Phase 2: Foundational (Blocking Prerequisites)

**Purpose**: Extend the shared package-directive model and ecosystem metadata so both JavaScript and Python stories can use the same validated per-directive version and isolated lifecycle representation.

**Checkpoint**: The typed/raw configuration model and registry reject invalid version usage before any build command is generated, while existing primary and unrelated package types remain compatible.

- [X] T004 [P] Add the per-directive `Version` field and YAML decoding support to `pkg/config/packages_directive.go` and `pkg/config/raw_packages_directive.go`
- [X] T005 [P] Define shared exact `X.Y.Z` validation and alternative-versus-primary version rules in `pkg/config/packages_directive.go`, including required versions for `javascript-yarn`, `javascript-pnpm`, `python-uv`, and `python-poetry` and rejection for all other package types
- [X] T006 [P] Add the internal `isAlternativeManager` switch helper in `pkg/config/packages_directive.go`, with cases only for Yarn, pnpm, uv, and Poetry, and use it instead of a registry boolean or duplicated type comparisons
- [X] T007 [P] Introduce the internal `PackageCommandWrapper` type/factory in `pkg/config/packages_directive.go` to centralize `cd` and environment-prefix composition and return the install-command function used by `PackageEcosystem`
- [X] T008 Wire version parsing, defaults, unknown-field behavior, and validation errors through the existing raw directive conversion in `pkg/config/raw_packages_directive.go`
- [X] T009 [P] Add Ginkgo/Gomega coverage for the alternative-manager switch, exact versions, omitted versions, malformed/ranged versions, versions on primary types, versions on unrelated ecosystems, wrapper output, and primary command compatibility in `pkg/config/raw_packages_directive_test.go` and the applicable `pkg/config/packages_directive_*_test.go` files

---

## Phase 3: User Story 1 - Install JavaScript dependencies with an unavailable alternative manager (Priority: P1) 🎯 MVP

**Goal**: Reject a pre-installed Yarn or pnpm executable; otherwise install the exact configured version inside one readable `if ... then ... else ... fi` block, run the frozen install through its isolated executable, and remove only the temporary prefix after success.

**Independent Test**: Build Yarn and pnpm fixtures without the alternative executable and execute negative cases with the selected executable pre-installed; verify the pre-installed-manager branch fails without cleanup, the absent-manager branch installs and removes its prefix, and the successful path produces locked dependencies and SBOM output.

### Tests for User Story 1

- [X] T010 [P] [US1] Add generated-command tests comparing the complete Yarn and pnpm wrapper snippets, including the pre-installed-manager branch that fails without cleanup and the absent-manager branch containing temporary-prefix creation, exact npm bootstrap with `--no-save --package-lock=false`, version verification, frozen dependency execution, prefix cleanup, and scope removal in one readable `if ... then ... else ... fi` block in `pkg/config/packages_commands_test.go`
- [X] T011 [P] [US1] Add wrapper-sequence failure tests proving pre-installed-manager rejection occurs before bootstrap without cleanup, bootstrap/version failures prevent dependency installation, and dependency failures preserve the original error without cleanup in `pkg/config/packages_commands_test.go`
- [X] T012 [P] [US1] Add primary JavaScript regression tests proving `javascript-npm` still generates only its existing `npm ci` behavior and does not bootstrap or clean up an alternative manager in `pkg/config/packages_commands_test.go` and `pkg/config/packages_directive_javascript_test.go`

### Implementation for User Story 1

- [X] T013 [US1] Configure `PackageCommandWrapper` for Yarn and pnpm in `pkg/config/packages_directive.go`, using a pre-installed-manager rejection branch plus an absent-manager branch with a unique temporary prefix, exact npm bootstrap using `--no-save --package-lock=false`, post-bootstrap version verification, dependency execution through the absolute prefix executable, and cleanup inside one readable `if ... then ... else ... fi` block
- [X] T014 [US1] Refactor Yarn and pnpm `InstallCmd` generation to use the command wrapper, invoke the isolated absolute executable for the existing frozen dependency command, and run ephemeral-prefix cleanup and scope removal inside the absent-manager `if ... then ... else ... fi` branch without mutating shared `PATH`
- [X] T015 [US1] Ensure Yarn and pnpm command content, configured versions, and workdirs flow into the existing package-stage checksum in `pkg/build/stage/packages.go` and `pkg/build/stage/packages_test.go`
- [X] T016 [P] [US1] Update the Yarn fixture configuration and builder image to use an exact version, provide npm, and omit preinstalled Yarn in `test/e2e/sbom/_fixtures/inject/yarn_simple/werf.yaml` and `test/e2e/sbom/_fixtures/inject/yarn_simple/Dockerfile.builder-base`
- [X] T017 [P] [US1] Update the pnpm fixture configuration and builder image to use an exact version, provide npm, and omit preinstalled pnpm in `test/e2e/sbom/_fixtures/inject/pnpm_simple/werf.yaml` and `test/e2e/sbom/_fixtures/inject/pnpm_simple/Dockerfile.builder-base`
- [X] T018 [P] [US1] Extend the Yarn acceptance scenario to assert exact-version dependency installation, pre-installed-manager rejection where representable, temporary-scope removal, and existing SBOM dependency visibility in `test/e2e/sbom/yarn_test.go`
- [X] T019 [P] [US1] Extend the pnpm acceptance scenario to assert exact-version dependency installation, pre-installed-manager rejection where representable, temporary-scope removal, and existing SBOM dependency visibility in `test/e2e/sbom/pnpm_test.go`

**Checkpoint**: Yarn and pnpm independently support isolated bootstrap, frozen installation, temporary-prefix cleanup, caching, and SBOM coverage without changing npm behavior.

---

## Phase 4: User Story 2 - Install Python dependencies with an unavailable alternative manager (Priority: P1)

**Goal**: Reject a pre-installed uv or Poetry executable; otherwise install the exact configured version inside one readable `if ... then ... else ... fi` block, run the locked install through its isolated executable, and remove only the temporary virtual environment after success.

**Independent Test**: Build uv and Poetry fixtures without the alternative executable and execute negative cases with the selected executable pre-installed; verify pre-installed-manager rejection without cleanup, absent-manager bootstrap and venv cleanup, locked dependencies, and SBOM output.

### Tests for User Story 2

- [X] T020 [P] [US2] Add generated-command tests comparing the complete uv and Poetry wrapper snippets, including the pre-installed-manager branch that fails without cleanup and the absent-manager branch containing venv creation, exact pip bootstrap, version verification, locked dependency execution, and venv cleanup in one readable `if ... then ... else ... fi` block in `pkg/config/packages_commands_test.go`
- [X] T021 [P] [US2] Add primary Python regression tests proving `python-pip` retains its current install command and does not add an alternative-manager wrapper in `pkg/config/packages_commands_test.go` and `pkg/config/packages_directive_python_test.go`
- [X] T022 [P] [US2] Add multi-directive tests proving separate Python directives do not share versions, bootstrap state, workdirs, or cleanup state in `pkg/config/packages_commands_test.go`

### Implementation for User Story 2

- [X] T023 [US2] Configure `PackageCommandWrapper` for uv and Poetry in `pkg/config/packages_directive.go`, using a pre-installed-manager rejection branch plus an absent-manager branch with `python3 -m venv <venv>`, exact pip bootstrap through the venv interpreter, post-bootstrap version verification, dependency execution through the absolute venv executable, and cleanup inside one readable `if ... then ... else ... fi` block
- [X] T024 [US2] Refactor uv and Poetry `InstallCmd` generation to use the command wrapper, invoke the isolated absolute executable for `uv sync --frozen` or `poetry sync --no-root`, and run ephemeral-venv cleanup inside the absent-manager `if ... then ... else ... fi` branch without mutating shared `PATH`
- [X] T025 [P] [US2] Update the uv fixture configuration and builder image to use an exact version, provide pip, and omit preinstalled uv in `test/e2e/sbom/_fixtures/inject/uv_simple/werf.yaml` and `test/e2e/sbom/_fixtures/inject/uv_simple/Dockerfile.builder-base`
- [X] T026 [P] [US2] Update the Poetry fixture configuration and builder image to use an exact version, provide pip, and omit preinstalled Poetry in `test/e2e/sbom/_fixtures/inject/poetry_simple/werf.yaml` and `test/e2e/sbom/_fixtures/inject/poetry_simple/Dockerfile.builder-base`
- [X] T027 [P] [US2] Extend the uv acceptance scenario to assert exact-version dependency installation, pre-installed-manager rejection where representable, temporary-venv removal, and existing SBOM dependency visibility in `test/e2e/sbom/uv_test.go`
- [X] T028 [P] [US2] Extend the Poetry acceptance scenario to assert exact-version dependency installation, pre-installed-manager rejection where representable, temporary-venv removal, and existing SBOM dependency visibility in `test/e2e/sbom/poetry_test.go`

**Checkpoint**: uv and Poetry independently support isolated bootstrap, locked installation, temporary-venv cleanup, caching, and SBOM coverage without changing pip behavior.

---

## Phase 5: User Story 3 - Preserve deterministic dependency installation and SBOM coverage (Priority: P1)

**Goal**: Prove the complete lifecycle remains deterministic and diagnosable across all four managers, including invalid locks, forbidden pre-installed managers, absent-manager cleanup failures, cache identity, and SBOM source paths.

**Independent Test**: Exercise successful and failing lifecycle sequences for each manager and verify lock enforcement, original failure preservation, pre-installed-manager rejection, cleanup semantics, package-stage invalidation, and SBOM dependency/cataloger behavior.

### Tests for User Story 3

- [X] T029 [P] [US3] Add isolated-lifecycle tests for pre-installed-manager rejection without cleanup, missing npm/python/venv prerequisite, invalid lock/install failure, temporary-prefix or venv cleanup failure, complete wrapper-snippet ordering, and exact bootstrap/dependency/cleanup operation context in `pkg/config/packages_commands_test.go`
- [X] T030 [P] [US3] Add package-stage tests proving generated manager versions and lifecycle commands affect package checksum while manifest/lock and managed-input SBOM paths remain unchanged in `pkg/build/stage/packages_test.go`
- [X] T031 [P] [US3] Add configuration tests covering multiple mixed JavaScript/Python directives and unchanged unsupported ecosystems in `pkg/config/packages_directive_test.go`

### Implementation for User Story 3

- [X] T032 [US3] Verify and adjust package-stage integration in `pkg/build/stage/packages.go` so wrapper-composed commands remain in the existing single network-enabled stage and no extra stage, shared global mutation, or independent lock scan is introduced
- [X] T033 [US3] Verify and adjust managed-input and cataloger integration so Yarn/pnpm retain JavaScript lock cataloging and uv/Poetry retain Python cataloging with unchanged workdir/spec/lock source paths in `pkg/config/packages_directive.go` and `pkg/build/stage/packages.go`
- [X] T034 [US3] Add or update invalid-lock failure assertions so dependency failures remain diagnosable and successful cleanup does not mask the original install failure in `test/e2e/sbom/alternative_manager_failures_test.go` and the existing invalid-lock fixtures under `test/e2e/sbom/_fixtures/negative/`

**Checkpoint**: All four alternative managers preserve deterministic lock installation, cache behavior, failure semantics, and SBOM coverage.

---

## Phase 6: Polish & Cross-Cutting Concerns

**Purpose**: Document the user-visible YAML contract and run the repository-required verification gates.

- [X] T035 [P] Document required exact `version` values, supported alternative-manager examples, primary-manager behavior, and builder-image prerequisites in `docs/pages_en/usage/build/stapel/instructions.md`
- [X] T036 [P] Document required exact `version` values, supported alternative-manager examples, primary-manager behavior, and builder-image prerequisites in `docs/pages_ru/usage/build/stapel/instructions.md`
- [X] T037 Run formatting and validate authored-file whitespace for the changed Go, test, fixture, and documentation files with `task format` and the scoped repository checks
- [X] T038 Run the feature build with `task build` and record the result against `Taskfile.dist.yaml` for the implementation handoff
- [X] T039 Run the one-time lint prerequisite with `task deps:install:golangci-lint` and record the installed tool state used by `Taskfile.dist.yaml`
- [X] T040 Run the repository lint gate with `task lint` and record any feature-related diagnostics for the changed `pkg/config/` and `pkg/build/stage/` files
- [X] T041 Run the unit-test gate with `task test:unit` and record any feature-related failures in `pkg/config/` and `pkg/build/stage/`
- [X] T042 [P] Run the Yarn e2e scenario in `test/e2e/sbom/yarn_test.go` with `task test:e2e paths="./test/e2e/sbom/..." labelFilter="yarn"`, covering pre-installed-manager rejection where representable and missing-manager isolation
- [X] T043 [P] Run the pnpm e2e scenario in `test/e2e/sbom/pnpm_test.go` with `task test:e2e paths="./test/e2e/sbom/..." labelFilter="pnpm"`, covering pre-installed-manager rejection where representable and missing-manager isolation
- [X] T044 [P] Run the uv e2e scenario in `test/e2e/sbom/uv_test.go` with `task test:e2e paths="./test/e2e/sbom/..." labelFilter="uv"`, covering pre-installed-manager rejection where representable and missing-manager isolation
- [X] T045 [P] Run the Poetry e2e scenario in `test/e2e/sbom/poetry_test.go` with `task test:e2e paths="./test/e2e/sbom/..." labelFilter="poetry"`, covering pre-installed-manager rejection where representable and missing-manager isolation
- [X] T046 Run the full legacy integration gate with `task test:integration` for `test/legacy_e2e/` and record any failures attributable to isolated manager installation, wrapper composition, or cleanup semantics in the implementation handoff

---

## Phase 7: Convergence

- [X] T047 Extend the Yarn, pnpm, uv, and Poetry success scenarios in `test/e2e/sbom/{yarn_test.go,pnpm_test.go,uv_test.go,poetry_test.go}` to verify that the temporary alternative-manager scope is absent from the resulting image per FR-006 / SC-002 / SC-009
- [X] T048 Run `task test:integration` against `test/legacy_e2e/` and record feature-related results for the remaining legacy integration gate per T046 / plan: quality gates (completed)

---

## Dependencies & Execution Order

### Phase Dependencies

- **Setup (Phase 1)**: No implementation dependency; confirms the existing surfaces and paths.
- **Foundational (Phase 2)**: Depends on Setup; blocks all user-story work because both manager families require the shared `Version` model, alternative-manager switch, and command-wrapper contract.
- **User Story 1 (Phase 3)**: Depends on Foundational; delivers the MVP JavaScript increment.
- **User Story 2 (Phase 4)**: Depends on Foundational; can proceed in parallel with US1 after the shared model work, although shared command-file edits should be coordinated.
- **User Story 3 (Phase 5)**: Depends on the lifecycle implementation from US1 and US2 because it validates all four managers and their shared stage/SBOM behavior.
- **Polish (Phase 6)**: Depends on the desired user stories being implemented; documentation can proceed in parallel with implementation, while gates run after code and fixture changes are complete.
- **Convergence (Phases 7–8)**: Depends on the implementation and validation phases; T047–T051 capture follow-up acceptance, diagnostics, readable lifecycle composition, and negative-fixture coverage.

### User Story Dependencies

- **US1 (P1)**: Foundational only; no dependency on US2.
- **US2 (P1)**: Foundational only; no dependency on US1.
- **US3 (P1)**: Depends on US1 and US2 lifecycle commands and fixtures, then validates cross-story behavior.

### Parallel Opportunities

- T006–T009 can be split by the alternative-manager switch, command-wrapper implementation, and tests after the completed raw/typed version model is reviewed.
- T016–T019 can run in parallel because Yarn and pnpm use separate fixtures/tests, while T010–T012 should coordinate edits to the shared command test file.
- T025–T028 can run in parallel because uv and Poetry use separate fixtures/tests, while T020–T022 should coordinate edits to the shared command test file.
- T029–T031 can run in parallel across command lifecycle, stage checksum, and mixed-directive configuration coverage.
- T035–T036 and T042–T045 can run in parallel once their respective implementation inputs are ready; T039 must precede T040.
- T047–T051 can be reviewed in parallel by success-path e2e, integration-gate, lifecycle-diagnostics, and negative-fixture owners; T051 depends on the generated rejection branch.

### Suggested dependency graph

```text
T001-T003
   |
T004-T009
   |
   +--> T010-T019 (US1: JavaScript)
   |
   +--> T020-T028 (US2: Python)
             |
             +--> T029-T034 (US3: deterministic lifecycle and SBOM)
                              |
                              +--> T035-T046 (polish and full validation)
                                             |
                                             +--> T047-T051 (convergence and negative e2e coverage)
```

---

## Parallel Example: User Story 1

```text
Developer A: T010-T012 — command and regression tests in pkg/config/
Developer B: T016 and T018 — Yarn fixture and e2e scenario
Developer C: T017 and T019 — pnpm fixture and e2e scenario
Developer D: T013-T015 — command-wrapper isolation, command composition, and package-stage checksum integration
```

## Parallel Example: User Story 2

```text
Developer A: T020-T022 — Python command and multi-directive tests in pkg/config/
Developer B: T025 and T027 — uv fixture and e2e scenario
Developer C: T026 and T028 — Poetry fixture and e2e scenario
Developer D: T023-T024 — Python command-wrapper isolation, command composition, and failure-context integration
```

---

## Implementation Strategy

### MVP First (User Story 1)

1. Complete Phase 1 and Phase 2.
2. Complete Phase 3 for Yarn and pnpm.
3. Run the scoped config/stage unit tests and the Yarn/pnpm e2e scenarios.
4. Stop and validate the JavaScript increment independently before proceeding.

### Incremental Delivery

1. Shared model and validation foundation.
2. US1: JavaScript alternative-manager bootstrap and cleanup.
3. US2: Python alternative-manager bootstrap and cleanup.
4. US3: deterministic failure, cache, multi-directive, and SBOM verification.
5. Documentation and full repository gates.
6. Convergence checks for temporary-scope removal, diagnostics, and pre-installed-manager negative fixtures.

### Notes

- Every task follows the required checklist format: checkbox, sequential task ID, optional `[P]`, optional story label in story phases, and a concrete file path.
- No new external dependency, build stage, package-manager service/interface hierarchy, or generated release file is planned; the registry reuses its existing install-command field with the internal switch and command-wrapper factory, with no shared environment mutation or pre-installed-manager reuse.
- Cleanup removes only the directive-local npm prefix or Python venv and is chained only after successful dependency installation; failed builds may retain temporary state for diagnosis as specified.

---

## Phase 8: Convergence

- [X] T049 Restructure the Yarn, pnpm, uv, and Poetry generated lifecycle commands in `pkg/config/packages_directive.go` into one readable `if ... then ... else ... fi` block per manager, with pre-installed-manager rejection in the `then` branch and isolated bootstrap, dependency installation, and successful scope cleanup in the `else` branch
- [X] T050 Add operation-specific diagnostics for bootstrap, version verification, dependency installation, and cleanup failures in `pkg/config/packages_directive.go` and `pkg/config/packages_commands_test.go`, preserving the original dependency error and successful-cleanup semantics
- [X] T051 Add pre-installed-manager fixtures and negative e2e coverage for Yarn, pnpm, uv, and Poetry in `test/e2e/sbom/alternative_manager_failures_test.go` and `test/e2e/sbom/_fixtures/negative/{yarn_preinstalled,pnpm_preinstalled,uv_preinstalled,poetry_preinstalled}/`, verifying rejection before bootstrap and absence of successful-installation cleanup
