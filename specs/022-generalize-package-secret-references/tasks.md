---

description: "Actionable task list for generalizing package secret references"
---

# Tasks: Generalize Package Secret References

**Input**: Design documents from `specs/022-generalize-package-secret-references/`

**Prerequisites**: `plan.md`, `spec.md`, `research.md`, `data-model.md`, `quickstart.md`; `contracts/` is intentionally empty because no external interface is added.

**Tests**: Included because the feature specification requires source-type, negative, compatibility, security, and cross-ecosystem verification.

## Phase 1: Setup (Shared Infrastructure)

**Purpose**: Confirm the existing package-command implementation and test harness are the implementation surface; no new module, dependency, storage, or public interface is required.

- [ ] T001 Record the existing package-command generation and secret-mount assumptions in the implementation work item, using `pkg/config/packages_commands.go`, `pkg/config/packages_directive.go`, `pkg/config/raw_stapel_image.go`, and `pkg/config/secrets.go`

---

## Phase 2: Foundational (Blocking Prerequisites)

**Purpose**: Add the internal data flow needed by every user story without exposing secret contents to command generation.

- [ ] T002 [P] Define an internal package-command options value containing only declared secret IDs, and update `GeneratePackagesCommands` in `pkg/config/packages_commands.go` to accept and propagate those options
- [ ] T003 [P] Update the `PackageEcosystem.InstallCmd` function type and all ecosystem entries in `pkg/config/packages_directive.go` to receive the shared package-command options without passing `Secret` values or resolved contents
- [ ] T004 Pass the validated `imageBase.Secrets` IDs into package-command generation from `rawStapelImage.toStapelImageBaseDirective` in `pkg/config/raw_stapel_image.go`, after `GetValidatedSecrets` succeeds and before `Shell.Packages` is populated

**Checkpoint**: All package directive types can receive declared-secret metadata, while secret contents remain outside generator inputs.

---

## Phase 3: User Story 1 - Use Any Build Secret as a Package Environment Value (Priority: P1) 🎯 MVP

**Goal**: Resolve any declared exact `/run/secrets/<secret-id>` reference in `packages.env` for every package ecosystem while preserving ordinary values.

**Independent Test**: Generate and execute a package command against a temporary mounted-secret directory for environment-, file-, and literal-backed declarations, and verify that `os-pm` and at least one non-`os-pm` command receives the secret content rather than the path.

### Tests for User Story 1

- [ ] T005 [P] [US1] Add Ginkgo/Gomega table coverage in `pkg/config/packages_commands_test.go` for exact declared references from environment-, file-, and literal-backed secrets, including repeated references and empty values
- [ ] T006 [P] [US1] Add command-shape and literal-preservation coverage in `pkg/config/packages_commands_test.go` for ordinary values, `${VARIABLE}` text, non-reference paths, sorted environment names, shell-special characters, and explicit-reference precedence over an inherited same-name value
- [ ] T007 [P] [US1] Add cross-ecosystem coverage in `pkg/config/packages_commands_test.go` proving the shared resolver is used by `os-pm` and at least one non-`os-pm` directive such as `go-mod` or `python-pip`

### Implementation for User Story 1

- [ ] T008 [US1] Implement exact `/run/secrets/<secret-id>` parsing and declared-ID validation in the shared environment resolver in `pkg/config/packages_commands.go`, leaving all non-exact values literal
- [ ] T009 [US1] Implement single-line inline environment serialization for validated secret references in `pkg/config/packages_commands.go`, reading the mounted file only in the package-stage shell and preserving existing quoting and key sorting
- [ ] T010 [US1] Replace direct `formatEnvVars` calls with the shared resolver across every package ecosystem in `pkg/config/packages_directive.go`, including `os-pm` and all non-`os-pm` install commands
- [ ] T011 [US1] Preserve explicit-reference precedence and ordinary environment behavior when composing package commands in `pkg/config/packages_commands.go`, without adding variable-name-specific expansion branches
- [ ] T012 [US1] Run the focused User Story 1 verification with `task test:unit paths="./pkg/config/..."` and confirm the generated command remains single-line and passes the resolved value only to the package-manager process

**Checkpoint**: User Story 1 is independently functional for declared references, ordinary values, `os-pm`, and a non-`os-pm` ecosystem.

---

## Phase 4: User Story 2 - Keep Secret Resolution Ephemeral and Safe (Priority: P1)

**Goal**: Reject invalid configured references before stage creation and prevent resolved secret content from entering commands, diagnostics, cache inputs, metadata, SBOM data, or the resulting image environment.

**Independent Test**: Parse configurations containing undeclared and unresolvable references, verify actionable content-free errors before package execution, then execute a valid package-stage command and inspect command text, diagnostics, and resulting environment for absence of the secret value.

### Tests for User Story 2

- [ ] T013 [P] [US2] Add parsing-failure coverage in `pkg/config/packages_commands_test.go` or the nearest existing raw image/config test file for undeclared references and environment-, file-, and literal-source resolution failures before package-manager execution
- [ ] T014 [P] [US2] Add no-leak assertions in `pkg/config/packages_commands_test.go` that resolved secret content is absent from generated command text and returned errors, including shell-special and repeated values
- [ ] T015 [P] [US2] Add compatibility coverage in `pkg/config/packages_commands_test.go` for `PACKAGES_VERSION` provenance-file generation and default behavior plus generalized `REGISTRY` handling
- [ ] T016 [P] [US2] Add package-stage coverage in the appropriate existing `pkg/build/stage/` test file, or add a focused fixture under `test/e2e/` only if unit tests cannot prove process-only delivery and non-persistence in the resulting image

### Implementation for User Story 2

- [ ] T017 [US2] Validate that every exact package environment reference names a declared secret and that its configured environment/file/literal source is resolvable during configuration conversion, using the existing validation path in `pkg/config/secrets.go` and `pkg/config/raw_stapel_image.go`
- [ ] T018 [US2] Return actionable configuration errors for undeclared or unresolvable references from `pkg/config/raw_stapel_image.go` without including secret contents, and ensure package commands are not generated after validation failure
- [ ] T019 [US2] Keep resolved values out of generated command strings, arguments, logs, cache identity, SBOM data, metadata, and persistent image environment by limiting command generation to reference syntax and mounted-file reads in `pkg/config/packages_commands.go`
- [ ] T020 [US2] Preserve `PACKAGES_VERSION` provenance writing and its default fallback, route `REGISTRY` through the generic reference primitive, and ensure explicit package environment entries take precedence in `pkg/config/packages_commands.go`
- [ ] T021 [US2] Run focused package-stage and configuration verification with `task test:unit paths="./pkg/config/..."` and `task test:unit paths="./pkg/build/stage/..."`, adding the labeled e2e command from `quickstart.md` only if T016 adds an e2e fixture

**Checkpoint**: User Story 2 is independently secure and compatible: invalid references fail before execution, valid values are ephemeral, and existing provenance/registry behavior remains intact.

---

## Phase 5: Polish & Cross-Cutting Concerns

**Purpose**: Run repository-required quality gates and confirm the change remains within the feature scope.

- [ ] T022 [P] Review `pkg/config/packages_commands.go`, `pkg/config/packages_directive.go`, `pkg/config/raw_stapel_image.go`, and `pkg/config/secrets.go` for accidental secret-content propagation, variable-name-specific expansion, Git credential behavior, or new public API
- [ ] T023 Format changed Go files with `task format` and inspect the authored diff for unintended changes
- [ ] T024 Build the repository with `task build`
- [ ] T025 Install the lint prerequisite with `task deps:install:golangci-lint` and run repository lint with `task lint`
- [ ] T026 Run the full unit suite with `task test:unit`
- [ ] T027 Run the scoped package e2e suite with `task test:e2e paths="./test/e2e/sbom/..." labelFilter="packages"` when the implementation adds the package fixture, then run `task test:integration`

---

## Dependencies & Execution Order

### Phase Dependencies

- **Setup (Phase 1)**: No dependencies; confirms the existing implementation surface.
- **Foundational (Phase 2)**: Depends on T001 and blocks both user stories because both require the options flow and declared secret IDs.
- **User Story 1 (Phase 3)**: Depends on T002-T004; is the MVP and establishes the shared resolver and ecosystem wiring.
- **User Story 2 (Phase 4)**: Depends on T008-T011 because validation and compatibility must protect the actual shared resolver; its test design can begin in parallel with US1 tests.
- **Polish (Phase 5)**: Depends on the desired user stories being implemented and their focused tests passing.

### User Story Dependencies

- **US1 (P1)**: Starts after Phase 2; no dependency on US2.
- **US2 (P1)**: Starts after Phase 2 and integrates with the resolver created for US1; security-specific tests and validation work are independently testable, but final compatibility verification uses the shared implementation.

### Parallel Opportunities

- T002 and T003 can be prepared in parallel because they touch separate files; T004 follows their API shape.
- T005-T007 can be written in parallel because they are disjoint test concerns in the same test file only if coordinated to avoid edit conflicts; otherwise execute sequentially within `pkg/config/packages_commands_test.go`.
- T013-T016 can be designed in parallel because they cover parsing errors, no-leak behavior, compatibility, and runtime persistence separately.
- T022 and the final validation commands can be run after implementation in parallel where the command environment permits, but `task format` must precede build/lint/test gates.

## Parallel Example: User Story 1

```text
Task: T005 Add source-type and repeated-reference tests in pkg/config/packages_commands_test.go
Task: T006 Add literal-preservation and precedence tests in pkg/config/packages_commands_test.go
Task: T007 Add os-pm and non-os-pm generic coverage in pkg/config/packages_commands_test.go

After tests are prepared:
Task: T008 Implement the exact-reference resolver in pkg/config/packages_commands.go
Task: T010 Update ecosystem wiring in pkg/config/packages_directive.go
```

## Parallel Example: User Story 2

```text
Task: T013 Add invalid-reference parsing tests in pkg/config/packages_commands_test.go
Task: T014 Add no-leak assertions in pkg/config/packages_commands_test.go
Task: T015 Add PACKAGES_VERSION and REGISTRY compatibility tests in pkg/config/packages_commands_test.go
Task: T016 Add package-stage persistence coverage in pkg/build/stage/ or test/e2e/
```

## Implementation Strategy

### MVP First (User Story 1 Only)

1. Complete Phase 1 and Phase 2.
2. Add and run the US1 tests for source types, ordinary values, exact references, and one non-`os-pm` ecosystem.
3. Implement the shared resolver and all ecosystem wiring.
4. Run `task test:unit paths="./pkg/config/..."` and confirm package-manager process delivery.
5. Stop for an independently testable MVP before adding security/compatibility hardening.

### Incremental Delivery

1. Phase 1 + Phase 2: establish the internal declared-ID flow.
2. US1: generalize exact secret references across package directives.
3. US2: enforce parse-time validation, no-leak guarantees, ephemeral lifetime, and compatibility defaults.
4. Polish: execute repository quality gates and any required package-stage/e2e verification.

## Notes

- Every task uses the required `- [ ] T###` checklist form; story tasks include `[US1]` or `[US2]`, and parallel tasks include `[P]` only where parallel work is practical.
- No external dependency, public interface, storage change, Git credential behavior, or generated documentation change is planned.
- `contracts/` is empty by design; there is no external contract task.
