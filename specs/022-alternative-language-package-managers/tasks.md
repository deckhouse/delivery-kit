---

# Tasks: Alternative Language Package Managers for Packages Directive

**Input**: Design documents from `/specs/022-alternative-language-package-managers/`

**Prerequisites**: `plan.md`, `spec.md`, `research.md`, `data-model.md`, `contracts/`, and `quickstart.md`

**Tests**: Included because the feature plan and constitution explicitly require co-located Ginkgo/Gomega unit tests and four dedicated e2e scenarios.

**Organization**: Tasks are grouped by user story. Shared configuration and registry work is foundational; each story then adds an independently testable lifecycle increment.

## Phase 1: Setup (Shared Infrastructure)

**Purpose**: Confirm the existing package-directive and e2e fixture surfaces before implementation; no new module or dependency setup is required.

- [ ] T001 Review the existing package directive, ecosystem registry, command-generation, stage checksum, and SBOM paths in `pkg/config/`, `pkg/build/stage/`, and `test/e2e/sbom/` against `specs/022-alternative-language-package-managers/contracts/`
- [ ] T002 [P] Identify the current Yarn, pnpm, uv, and Poetry fixture inputs and assertions in `test/e2e/sbom/_fixtures/inject/` and `test/e2e/sbom/*_test.go` without changing generated or release-managed files
- [ ] T003 [P] Confirm the package-directive documentation sections to update in `docs/pages_en/usage/build/stapel/instructions.md` and `docs/pages_ru/usage/build/stapel/instructions.md`

---

## Phase 2: Foundational (Blocking Prerequisites)

**Purpose**: Extend the shared package-directive model and ecosystem metadata so both JavaScript and Python stories can use the same validated per-directive version and lifecycle representation.

**Checkpoint**: The typed/raw configuration model and registry reject invalid version usage before any build command is generated, while existing primary and unrelated package types remain compatible.

- [ ] T004 [P] Add the per-directive `Version` field and YAML decoding support to `pkg/config/packages_directive.go` and `pkg/config/raw_packages_directive.go`
- [ ] T005 [P] Define shared exact `X.Y.Z` validation and alternative-versus-primary version rules in `pkg/config/packages_directive.go`, including required versions for `javascript-yarn`, `javascript-pnpm`, `python-uv`, and `python-poetry` and rejection for all other package types
- [ ] T006 [P] Extend the existing ecosystem registry metadata in `pkg/config/packages_directive.go` with alternative manager executable, bootstrap tool/package, and cleanup information without introducing a new public interface
- [ ] T007 Wire version parsing, defaults, unknown-field behavior, and validation errors through the existing raw directive conversion in `pkg/config/raw_packages_directive.go`
- [ ] T008 [P] Add Ginkgo/Gomega parsing and validation coverage for exact versions, omitted versions, malformed/ranged versions, versions on primary types, and versions on unrelated ecosystems in `pkg/config/raw_packages_directive_test.go` and the applicable `pkg/config/packages_directive_*_test.go` files
- [ ] T009 [P] Add registry metadata and directive-model coverage for all four alternative managers and unchanged primary-manager defaults in `pkg/config/packages_directive_javascript_test.go` and `pkg/config/packages_directive_python_test.go`

---

## Phase 3: User Story 1 - Install JavaScript dependencies with an unavailable alternative manager (Priority: P1) 🎯 MVP

**Goal**: Bootstrap Yarn or pnpm at the exact configured version through npm, run the existing frozen install, and remove only the temporary manager after success.

**Independent Test**: Build the Yarn and pnpm fixtures with npm present and the selected alternative manager absent; verify locked dependencies and SBOM output, then verify the selected manager is absent from the successful result.

### Tests for User Story 1

- [ ] T010 [P] [US1] Add generated-command tests for Yarn and pnpm pre-existing-manager detection, exact npm bootstrap, frozen dependency installation, and success-only cleanup ordering in `pkg/config/packages_commands_test.go`
- [ ] T011 [P] [US1] Add failure-ordering tests proving bootstrap/version failures prevent dependency installation and dependency failures preserve the original error without running successful-install cleanup in `pkg/config/packages_commands_test.go`
- [ ] T012 [P] [US1] Add primary JavaScript regression tests proving `javascript-npm` still generates only its existing `npm ci` behavior and does not bootstrap or clean up an alternative manager in `pkg/config/packages_commands_test.go` and `pkg/config/packages_directive_javascript_test.go`

### Implementation for User Story 1

- [ ] T013 [US1] Generate directive-local Yarn and pnpm shell sequences in `pkg/config/packages_commands.go` with executable absence checks, exact npm package versions, existing frozen install commands, and cleanup chained only after successful installation
- [ ] T014 [US1] Preserve per-directive environment, workdir, manifest/lock paths, and actionable bootstrap/install/cleanup error context for JavaScript alternative commands in `pkg/config/packages_commands.go`
- [ ] T015 [US1] Ensure Yarn and pnpm command content, configured versions, and workdirs flow into the existing package-stage checksum in `pkg/build/stage/packages.go` and `pkg/build/stage/packages_test.go`
- [ ] T016 [P] [US1] Update the Yarn fixture configuration and builder image to use an exact version, provide npm, and omit preinstalled Yarn in `test/e2e/sbom/_fixtures/inject/yarn_simple/werf.yaml` and `test/e2e/sbom/_fixtures/inject/yarn_simple/Dockerfile.builder-base`
- [ ] T017 [P] [US1] Update the pnpm fixture configuration and builder image to use an exact version, provide npm, and omit preinstalled pnpm in `test/e2e/sbom/_fixtures/inject/pnpm_simple/werf.yaml` and `test/e2e/sbom/_fixtures/inject/pnpm_simple/Dockerfile.builder-base`
- [ ] T018 [P] [US1] Extend the Yarn acceptance scenario to assert exact-version dependency installation, temporary-manager removal, and existing SBOM dependency visibility in `test/e2e/sbom/yarn_test.go`
- [ ] T019 [P] [US1] Extend the pnpm acceptance scenario to assert exact-version dependency installation, temporary-manager removal, and existing SBOM dependency visibility in `test/e2e/sbom/pnpm_test.go`

**Checkpoint**: Yarn and pnpm independently support ephemeral bootstrap, frozen installation, cleanup, caching, and SBOM coverage without changing npm behavior.

---

## Phase 4: User Story 2 - Install Python dependencies with an unavailable alternative manager (Priority: P1)

**Goal**: Bootstrap uv or Poetry at the exact configured version through pip, run the existing locked install, and remove only the temporary manager after success.

**Independent Test**: Build the uv and Poetry fixtures with pip present and the selected alternative manager absent; verify locked dependencies and SBOM output, then verify the selected manager is absent from the successful result.

### Tests for User Story 2

- [ ] T020 [P] [US2] Add generated-command tests for uv and Poetry pre-existing-manager detection, exact pip bootstrap, existing frozen/sync install commands, and success-only cleanup ordering in `pkg/config/packages_commands_test.go`
- [ ] T021 [P] [US2] Add primary Python regression tests proving `python-pip` retains its current install command and does not bootstrap or clean up an alternative manager in `pkg/config/packages_commands_test.go` and `pkg/config/packages_directive_python_test.go`
- [ ] T022 [P] [US2] Add multi-directive tests proving separate Python directives do not share versions, bootstrap state, workdirs, or cleanup state in `pkg/config/packages_commands_test.go`

### Implementation for User Story 2

- [ ] T023 [US2] Generate directive-local uv and Poetry shell sequences in `pkg/config/packages_commands.go` with executable absence checks, exact pip package versions, existing locked install commands, and cleanup chained only after successful installation
- [ ] T024 [US2] Preserve per-directive environment, workdir, manifest/lock paths, and actionable bootstrap/install/cleanup error context for Python alternative commands in `pkg/config/packages_commands.go`
- [ ] T025 [P] [US2] Update the uv fixture configuration and builder image to use an exact version, provide pip, and omit preinstalled uv in `test/e2e/sbom/_fixtures/inject/uv_simple/werf.yaml` and `test/e2e/sbom/_fixtures/inject/uv_simple/Dockerfile.builder-base`
- [ ] T026 [P] [US2] Update the Poetry fixture configuration and builder image to use an exact version, provide pip, and omit preinstalled Poetry in `test/e2e/sbom/_fixtures/inject/poetry_simple/werf.yaml` and `test/e2e/sbom/_fixtures/inject/poetry_simple/Dockerfile.builder-base`
- [ ] T027 [P] [US2] Extend the uv acceptance scenario to assert exact-version dependency installation, temporary-manager removal, and existing SBOM dependency visibility in `test/e2e/sbom/uv_test.go`
- [ ] T028 [P] [US2] Extend the Poetry acceptance scenario to assert exact-version dependency installation, temporary-manager removal, and existing SBOM dependency visibility in `test/e2e/sbom/poetry_test.go`

**Checkpoint**: uv and Poetry independently support ephemeral bootstrap, locked installation, cleanup, caching, and SBOM coverage without changing pip behavior.

---

## Phase 5: User Story 3 - Preserve deterministic dependency installation and SBOM coverage (Priority: P1)

**Goal**: Prove the complete lifecycle remains deterministic and diagnosable across all four managers, including invalid locks, pre-existing managers, cleanup failures, cache identity, and SBOM source paths.

**Independent Test**: Exercise successful and failing lifecycle sequences for each manager and verify lock enforcement, original failure preservation, pre-existing-manager rejection, cleanup semantics, package-stage invalidation, and SBOM dependency/cataloger behavior.

### Tests for User Story 3

- [ ] T029 [P] [US3] Add lifecycle command tests for pre-existing manager rejection, missing bootstrap prerequisite, invalid lock/install failure, cleanup failure, and exact operation-specific error context in `pkg/config/packages_commands_test.go`
- [ ] T030 [P] [US3] Add package-stage tests proving generated manager versions and lifecycle commands affect package checksum while manifest/lock and managed-input SBOM paths remain unchanged in `pkg/build/stage/packages_test.go`
- [ ] T031 [P] [US3] Add configuration tests covering multiple mixed JavaScript/Python directives and unchanged unsupported ecosystems in `pkg/config/packages_directive_test.go` and `pkg/config/raw_packages_directive_test.go`

### Implementation for User Story 3

- [ ] T032 [US3] Verify and adjust package-stage integration in `pkg/build/stage/packages.go` so all generated alternative-manager commands remain in the existing single network-enabled stage and no extra stage or lock scan is introduced
- [ ] T033 [US3] Verify and adjust managed-input and cataloger integration so Yarn/pnpm retain JavaScript lock cataloging and uv/Poetry retain Python cataloging with unchanged workdir/spec/lock source paths in `pkg/config/packages_directive.go` and `pkg/build/stage/packages.go`
- [ ] T034 [US3] Add or update failure-path assertions in the four manager e2e scenarios so dependency failures are diagnosable and successful cleanup does not mask the original install failure in `test/e2e/sbom/yarn_test.go`, `test/e2e/sbom/pnpm_test.go`, `test/e2e/sbom/uv_test.go`, and `test/e2e/sbom/poetry_test.go`

**Checkpoint**: All four alternative managers preserve deterministic lock installation, cache behavior, failure semantics, and SBOM coverage.

---

## Phase 6: Polish & Cross-Cutting Concerns

**Purpose**: Document the user-visible YAML contract and run the repository-required verification gates.

- [ ] T035 [P] Document required exact `version` values, supported alternative-manager examples, primary-manager behavior, and builder-image prerequisites in `docs/pages_en/usage/build/stapel/instructions.md`
- [ ] T036 [P] Document required exact `version` values, supported alternative-manager examples, primary-manager behavior, and builder-image prerequisites in `docs/pages_ru/usage/build/stapel/instructions.md`
- [ ] T037 Run formatting and validate authored-file whitespace for the changed Go, test, fixture, and documentation files with `task format` and the scoped repository checks
- [ ] T038 Run the feature's build, lint, and unit gates with `task build`, `task deps:install:golangci-lint`, `task lint`, and `task test:unit`
- [ ] T039 [P] Run the dedicated Yarn, pnpm, uv, and Poetry e2e scenarios with `task test:e2e paths="./test/e2e/sbom/..." labelFilter="yarn"`, `labelFilter="pnpm"`, `labelFilter="uv"`, and `labelFilter="poetry"`
- [ ] T040 Run the full legacy integration gate with `task test:integration` and record any failures attributable to this feature in the implementation handoff

---

## Dependencies & Execution Order

### Phase Dependencies

- **Setup (Phase 1)**: No implementation dependency; confirms the existing surfaces and paths.
- **Foundational (Phase 2)**: Depends on Setup; blocks all user-story work because both manager families require the shared `Version` model and registry metadata.
- **User Story 1 (Phase 3)**: Depends on Foundational; delivers the MVP JavaScript increment.
- **User Story 2 (Phase 4)**: Depends on Foundational; can proceed in parallel with US1 after the shared model work, although shared command-file edits should be coordinated.
- **User Story 3 (Phase 5)**: Depends on the lifecycle implementation from US1 and US2 because it validates all four managers and their shared stage/SBOM behavior.
- **Polish (Phase 6)**: Depends on the desired user stories being implemented; documentation can proceed in parallel with implementation, while gates run after code and fixture changes are complete.

### User Story Dependencies

- **US1 (P1)**: Foundational only; no dependency on US2.
- **US2 (P1)**: Foundational only; no dependency on US1.
- **US3 (P1)**: Depends on US1 and US2 lifecycle commands and fixtures, then validates cross-story behavior.

### Parallel Opportunities

- T004–T006 and T008–T009 can be split by raw model, typed validation, registry metadata, and tests after the existing APIs are reviewed.
- T016–T019 can run in parallel because Yarn and pnpm use separate fixtures/tests, while T010–T012 should coordinate edits to the shared command test file.
- T025–T028 can run in parallel because uv and Poetry use separate fixtures/tests, while T020–T022 should coordinate edits to the shared command test file.
- T029–T031 can run in parallel across command lifecycle, stage checksum, and mixed-directive configuration coverage.
- T035–T036 and the four manager-specific e2e commands in T039 can run in parallel once their respective implementation inputs are ready.

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
                              +--> T035-T040 (polish and full validation)
```

---

## Parallel Example: User Story 1

```text
Developer A: T010-T012 — command and regression tests in pkg/config/
Developer B: T016 and T018 — Yarn fixture and e2e scenario
Developer C: T017 and T019 — pnpm fixture and e2e scenario
Developer D: T013-T015 — command generation and package-stage checksum integration
```

## Parallel Example: User Story 2

```text
Developer A: T020-T022 — Python command and multi-directive tests in pkg/config/
Developer B: T025 and T027 — uv fixture and e2e scenario
Developer C: T026 and T028 — Poetry fixture and e2e scenario
Developer D: T023-T024 — Python command generation and failure-context integration
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

### Notes

- Every task follows the required checklist format: checkbox, sequential task ID, optional `[P]`, optional story label in story phases, and a concrete file path.
- No new external dependency, build stage, public manager interface, or generated release file is planned.
- Cleanup is chained only after successful dependency installation; failed builds may retain temporary manager state for diagnosis as specified.
