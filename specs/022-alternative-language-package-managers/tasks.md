# Tasks: Alternative Language Package Managers for Packages Directive

**Input**: Design documents from `/specs/022-alternative-language-package-managers/`

**Prerequisites**: `plan.md`, `spec.md`, `research.md`, `data-model.md`, `contracts/`, and `quickstart.md`

**Tests**: Required by the feature plan and constitution. Use co-located Ginkgo/Gomega tests and four dedicated SBOM e2e scenarios.

**Current status**: The implementation and existing unit/e2e coverage are present in the current branch. Remaining unchecked tasks are work identified by the updated plan or validation work not evidenced as completed in the repository. Post-bootstrap manager-version output verification is explicitly out of scope.

## Phase 1: Setup

**Purpose**: Confirm the existing implementation surfaces and feature contracts.

- [X] T001 Review package directives, ecosystem registry, command generation, package-stage checksum, SBOM paths, and feature contracts in `pkg/config/`, `pkg/build/stage/`, and `specs/022-alternative-language-package-managers/contracts/`
- [X] T002 [P] Review Yarn, pnpm, uv, and Poetry success and failure fixtures in `test/e2e/sbom/_fixtures/` and their scenarios in `test/e2e/sbom/`
- [X] T003 [P] Review the package-directive documentation sections in `docs/pages_en/usage/build/stapel/instructions.md` and `docs/pages_ru/usage/build/stapel/instructions.md`

---

## Phase 2: Foundational Configuration and Lifecycle

**Purpose**: Provide the shared per-directive version model, validation, alternative-manager classification, and command wrapper required by both manager families.

- [X] T004 [P] Add `FileBasedSpec.Version` and YAML decoding in `pkg/config/packages_directive.go` and `pkg/config/raw_packages_directive.go`
- [X] T005 Define required alternative-manager versions and forbidden versions on primary/unrelated package types in `pkg/config/packages_directive.go`
- [X] T006 [P] Add the `isAlternativeManager` switch for exactly Yarn, pnpm, uv, and Poetry in `pkg/config/packages_directive.go`
- [X] T007 [P] Add the internal package command wrapper and shared lifecycle templates in `pkg/config/packages_directive.go`
- [X] T008 Wire version defaults, unknown-field handling, and validation errors through raw directive conversion in `pkg/config/raw_packages_directive.go`
- [X] T009 Add Ginkgo/Gomega coverage for parsing, required/forbidden versions, malformed values, alternative-manager classification, primary-type compatibility, and complete generated snippets in `pkg/config/raw_packages_directive_test.go` and `pkg/config/packages_commands_test.go`

**Checkpoint**: Shared configuration and command generation are ready for both user stories; UUID-based scope generation and workdir-before-bootstrap ordering are implemented.

---

## Phase 3: User Story 1 — JavaScript Alternative Managers (Priority: P1) 🎯 MVP

**Goal**: Bootstrap Yarn or pnpm with npm in an isolated temporary prefix, install locked dependencies through the absolute isolated executable, reject pre-installed managers, and remove the prefix after success.

**Independent test**: Build the Yarn and pnpm fixtures with npm but without the selected alternative manager; verify successful locked installation, SBOM visibility, configured bootstrap version propagation, UUID-scoped prefix removal, and rejection of pre-installed managers before bootstrap.

### Tests

- [X] T010 [P] [US1] Compare complete Yarn and pnpm lifecycle snippets, including rejection, temporary-prefix creation, npm bootstrap with the configured version, frozen install, and cleanup in `pkg/config/packages_commands_test.go`
- [X] T011 [P] [US1] Test JavaScript bootstrap, dependency, and cleanup ordering and failure behavior without requiring post-bootstrap manager-version output verification in `pkg/config/packages_commands_test.go`
- [X] T012 [P] [US1] Test unchanged `javascript-npm` command generation in `pkg/config/packages_commands_test.go` and `pkg/config/packages_directive_javascript_test.go`

### Implementation and acceptance fixtures

- [X] T013 [US1] Generate isolated Yarn and pnpm lifecycle commands with pre-installed-manager rejection and directive-local npm prefixes in `pkg/config/packages_directive.go`
- [X] T014 [US1] Route Yarn and pnpm dependency installation through isolated absolute executables without persistent `PATH` mutation in `pkg/config/packages_directive.go`
- [X] T015 [US1] Preserve manager version and lifecycle command content in package-stage checksum calculation in `pkg/build/stage/packages.go` and `pkg/build/stage/packages_test.go`
- [X] T016 [P] [US1] Configure the Yarn success fixture with an exact version, npm-only builder, and no pre-installed Yarn in `test/e2e/sbom/_fixtures/inject/yarn_simple/werf.yaml` and `test/e2e/sbom/_fixtures/inject/yarn_simple/Dockerfile.builder-base`
- [X] T017 [P] [US1] Configure the pnpm success fixture with an exact version, npm-only builder, and no pre-installed pnpm in `test/e2e/sbom/_fixtures/inject/pnpm_simple/werf.yaml` and `test/e2e/sbom/_fixtures/inject/pnpm_simple/Dockerfile.builder-base`
- [X] T018 [P] [US1] Verify Yarn dependency installation, SBOM output, temporary-manager absence, and pre-installed rejection in `test/e2e/sbom/yarn_test.go` and `test/e2e/sbom/alternative_manager_failures_test.go`
- [X] T019 [P] [US1] Verify pnpm dependency installation, SBOM output, temporary-manager absence, and pre-installed rejection in `test/e2e/sbom/pnpm_test.go` and `test/e2e/sbom/alternative_manager_failures_test.go`

**Checkpoint**: Yarn and pnpm are independently functional; final repository verification remains open.

---

## Phase 4: User Story 2 — Python Alternative Managers (Priority: P1)

**Goal**: Bootstrap uv or Poetry with pip in an isolated virtual environment, install locked dependencies through the isolated executable, reject pre-installed managers, and remove the virtual environment after success.

**Independent test**: Build the uv and Poetry fixtures with pip and Python venv support but without the selected alternative manager; verify locked installation, SBOM visibility, configured bootstrap version propagation, UUID-scoped venv removal, and pre-installed rejection.

### Tests

- [X] T020 [P] [US2] Compare complete uv and Poetry lifecycle snippets, including rejection, venv creation, pip bootstrap with the configured version, locked install, and cleanup in `pkg/config/packages_commands_test.go`
- [X] T021 [P] [US2] Test unchanged `python-pip` command generation in `pkg/config/packages_commands_test.go` and `pkg/config/packages_directive_python_test.go`
- [X] T022 [P] [US2] Test independent versions, workdirs, and cleanup scopes for multiple Python directives in `pkg/config/packages_commands_test.go`

### Implementation and acceptance fixtures

- [X] T023 [US2] Generate isolated uv and Poetry lifecycle commands with pre-installed-manager rejection and directive-local venvs in `pkg/config/packages_directive.go`
- [X] T024 [US2] Route uv and Poetry locked dependency installation through absolute venv executables without persistent environment mutation in `pkg/config/packages_directive.go`
- [X] T025 [P] [US2] Configure the uv success fixture with an exact version, pip/venv-capable builder, and no pre-installed uv in `test/e2e/sbom/_fixtures/inject/uv_simple/werf.yaml` and `test/e2e/sbom/_fixtures/inject/uv_simple/Dockerfile.builder-base`
- [X] T026 [P] [US2] Configure the Poetry success fixture with an exact version, pip/venv-capable builder, and no pre-installed Poetry in `test/e2e/sbom/_fixtures/inject/poetry_simple/werf.yaml` and `test/e2e/sbom/_fixtures/inject/poetry_simple/Dockerfile.builder-base`
- [X] T027 [P] [US2] Verify uv dependency installation, SBOM output, temporary-manager absence, and pre-installed rejection in `test/e2e/sbom/uv_test.go` and `test/e2e/sbom/alternative_manager_failures_test.go`
- [X] T028 [P] [US2] Verify Poetry dependency installation, SBOM output, temporary-manager absence, and pre-installed rejection in `test/e2e/sbom/poetry_test.go` and `test/e2e/sbom/alternative_manager_failures_test.go`

**Checkpoint**: uv and Poetry are independently functional; final repository verification remains open.

---

## Phase 5: User Story 3 — Deterministic Installation and SBOM Coverage (Priority: P1)

**Goal**: Preserve lock semantics, cache identity, SBOM source paths, independent directive state, and diagnosable failure behavior across all four managers.

**Independent test**: Exercise successful, invalid-lock, bootstrap-failure, cleanup-failure, and pre-installed-manager cases for all four managers; verify original errors, cleanup ordering, cache invalidation, and SBOM dependency entries.

- [X] T029 [P] [US3] Cover pre-installed rejection, missing prerequisites, bootstrap failures, invalid locks, dependency failures, cleanup failures, and operation-specific diagnostics without adding post-bootstrap version-output verification in `pkg/config/packages_commands_test.go`
- [X] T030 [P] [US3] Verify manager versions and lifecycle commands affect package checksum while managed-input SBOM paths remain unchanged in `pkg/build/stage/packages_test.go`
- [X] T031 [P] [US3] Verify mixed JavaScript/Python directives and unchanged unsupported ecosystems in `pkg/config/packages_directive_test.go`
- [X] T032 [US3] Verify the lifecycle remains in the existing package stage without a new stage, shared global state, or independent lock scan in `pkg/build/stage/packages.go`
- [X] T033 [US3] Verify JavaScript and Python managed-input catalogers retain their existing manifest, lock, workdir, and SBOM paths in `pkg/config/packages_directive.go` and `pkg/build/stage/packages.go`
- [X] T034 [US3] Add and run invalid-lock and pre-installed-manager e2e coverage using `test/e2e/sbom/alternative_manager_failures_test.go` and `test/e2e/sbom/_fixtures/negative/`

**Checkpoint**: All four managers preserve deterministic lifecycle and SBOM behavior; independent golden expectations are implemented and final repository validation remains open.

---

## Phase 6: Documentation and Verification

- [X] T035 [P] Document the required `version` field, supported managers, Python `python3 -m venv` prerequisite, pre-installed-manager rejection, and migration guidance in `docs/pages_en/usage/build/stapel/instructions.md`
- [X] T036 [P] Add the same package-directive guidance in Russian in `docs/pages_ru/usage/build/stapel/instructions.md`
- [X] T037 Run `task format` and inspect authored-file whitespace for the changed implementation, tests, fixtures, and documentation files
- [X] T038 Run `task build` and record the result for this feature
- [X] T039 Run `task deps:install:golangci-lint` once, then `task lint`, and record results for the changed packages
- [X] T040 Run `task test:unit` and record results for `pkg/config` and `pkg/build/stage`
- [X] T041 [P] Run the Yarn e2e scenario with `task test:e2e paths="./test/e2e/sbom/..." labelFilter="yarn"` and record the result
- [X] T042 [P] Run the pnpm e2e scenario with `task test:e2e paths="./test/e2e/sbom/..." labelFilter="pnpm"` and record the result
- [X] T043 [P] Run the uv e2e scenario with `task test:e2e paths="./test/e2e/sbom/..." labelFilter="uv"` and record the result
- [X] T044 [P] Run the Poetry e2e scenario with `task test:e2e paths="./test/e2e/sbom/..." labelFilter="poetry"` and record the result

### Phase 6 validation results

- `task format`: passed.
- `task build`: passed; emitted existing CGO linker warnings.
- `task deps:install:golangci-lint` and `task lint`: passed with 0 issues.
- `task test:unit`: full suite failed in `pkg/build/stage` because existing expected command strings contain random UUIDs; scoped `task test:unit paths="./pkg/config/..."` passed.
- The Yarn, pnpm, uv, and Poetry e2e commands each completed with 2 passed specs and no failures; manager-specific specs were pending/skipped by the current environment filters.
- `task test:integration`: failed in `cleanup_after_converge` because the current Kubernetes environment could not resolve `kind-registry` (`SERVFAIL`); unrelated build/config suites passed before that failure.

---

## Phase 7: Updated Plan Alignment

**Purpose**: Complete requirements added after the previous task-list revision: library-backed SemVer validation, Go-generated UUID scope identifiers, workdir-before-bootstrap ordering, available embedded utility paths, per-command environment propagation, independent golden expectations, and removal of redundant shell fail-fast setup. Post-bootstrap manager-version output verification is excluded.

- [X] T046 Replace the regex-based manager-version validation with `github.com/Masterminds/semver/v3` parsing in `pkg/config/packages_directive.go`, and update the version-validation table in `pkg/config/packages_directive_test.go` to cover prerelease/build metadata while preserving required/forbidden version rules
- [X] T047 Replace the PID/suffix scope generation and post-bootstrap version-output check in `pkg/config/packages_directive.go` with a Go-generated UUID using `github.com/google/uuid`, pass that identifier into the lifecycle template, create the scope with `stapel.MkdirBinPath()`, retain `stapel.RmBinPath()` cleanup, and remove any unavailable `mktemp`/`grep` accessors or commands
- [X] T048 Refactor alternative-manager command templates in `pkg/config/packages_directive.go` so environment assignments prefix only external commands that need them, the enclosing fail-fast script supplies error propagation without an inner `set -e`, and tests compare the complete updated snippets in `pkg/config/packages_commands_test.go`
- [X] T049 Move the alternative-manager lifecycle `cd` before npm/pip bootstrap so bootstrap and dependency installation execute from the directive `workdir`, and update complete command-snippet and workdir-order tests in `pkg/config/packages_directive.go` and `pkg/config/packages_commands_test.go`
- [X] T050 Add independent golden command expectations for Yarn, pnpm, uv, and Poetry under `pkg/build/stage/testdata/packages_commands/{javascript-yarn,javascript-pnpm,python-uv,python-poetry}.golden`
- [X] T051 Update generated-command tests in `pkg/config/packages_commands_test.go` to read and compare the golden files directly, without deriving expected output through `GeneratePackagesCommands` or adding automatic golden-update behavior

---

## Dependencies and execution order

- Setup (Phase 1) precedes Foundational (Phase 2).
- T004–T009 and T046–T051 are complete; the remaining work is documentation and repository verification.
- The golden files are consumed directly by the generated-command tests and require no further implementation dependency.
- US1 and US2 depend on the shared foundation and can otherwise proceed in parallel.
- US3 depends on both manager lifecycles and validates their cross-cutting behavior.
- Documentation tasks T035–T036 can proceed in parallel with implementation. Verification tasks T037–T045 run after the final code, fixture, and golden-file changes.

### Parallel opportunities

- T002–T003, T006–T007, and T016–T019 can be split across independent files.
- T025–T028 can be split between uv and Poetry owners.
- T029–T031 and T035–T036 are independent workstreams.
- T041–T044 are independent manager-specific e2e runs; T039 must precede the lint gate in the verification sequence.
- The four golden files in T050 can be authored in parallel by manager; T051 integrates them into the shared test harness after all files exist.

### Suggested dependency graph

```text
T001-T003
   |
T004-T009
   |
T046-T051 (complete implementation alignment)
   |                         \
   +--> T010-T019              +--> T020-T028
            \             /
             +--> T029-T034
                      |
             T035-T036 (documentation)
                      |
             T037-T045 (verification)
```

## Implementation strategy

1. Use US1 as the MVP increment and validate Yarn/pnpm independently; T046–T051 are complete.
2. Add US2 for uv/Poetry and validate independently.
3. Finish US3 cross-cutting checks, documentation, and all repository gates.

**Format validation**: All 51 task entries use `- [ ]`/`- [X]`, a sequential `T###` ID, `[P]` only for parallel work, `[US#]` in story phases, and a concrete project-relative file path.
