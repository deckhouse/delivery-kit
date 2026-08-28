# Tasks: Local Execution Workflow

**Input**: Design documents from `/specs/020-execution-workflow/`

**Prerequisites**: `plan.md`, `spec.md`, `research.md`, `data-model.md`, `contracts/execution-workflow.yml.md`, `quickstart.md`

**Tests**: No automated test tasks are included for this workflow-only feature.

**Organization**: Tasks are grouped by user story. All three stories are P1 and together form one incrementally deliverable execution workflow.

## Phase 1: Setup (Shared Infrastructure)

**Purpose**: Establish the workflow source location and confirm the existing runtime conventions.

- [X] T001 [P] Create the project-local workflow directory `.specify/workflows/execution/` for the `execution` workflow definition
- [X] T002 Inspect `.specify/workflows/speckit/workflow.yml` and the supplied workflow architecture to record the exact `command`, `shell`, `if`, `while`, `do-while`, `continue_on_error`, step-output, and `max_iterations` shapes required by `.specify/workflows/execution/workflow.yml`

---

## Phase 2: Foundational (Blocking Prerequisites)

**Purpose**: Prepare shared workflow registration before user-story implementation.

- [X] T003 Update `.specify/workflows/workflow-registry.json` with synchronized local metadata for workflow ID `execution`, version `1.0.0`, description, and source path `.specify/workflows/execution/workflow.yml`
- [X] T004 Confirm the selected Spec Kit runtime exposes `speckit.implement`, `speckit.converge`, the `from_json` filter, and persisted step outputs required by the workflow contract in `.specify/workflows/`

**Checkpoint**: The source location, registry
 entry, and runtime prerequisites are ready for workflow implementation.

---

## Phase 3: User Story 1 - Run the local execution loop (Priority: P1) 🎯 MVP

**Goal**: Provide a standalone `execution` workflow that runs against `.specify/feature.json`, accepts an optional integration override, installs the linter once, and invokes implementation, lint, unit tests, and convergence in order.

**Independent Verification**: With a valid current feature, run `specify workflow run execution` and verify that l
inter installation occurs once before the loop, the first implementation invocation receives empty arguments, lint precedes unit tests, and convergence follows both successful checks. Repeat with `-i integration=claude` and verify the selected integration is passed to AI command steps.

### Implementation for User Story 1

- [X] T005 [US1] Implement `.specify/workflows/execution/workflow.yml` with workflow ID `execution`, version `1.0.0`, an `integration` input defaulting to `auto`, no `spec` input, one pre-loop `task deps:install:golangci-lint` shell step, and an outer `do-while` loop configured with built-in `max_iterations: 10`
- [X] T006 [US1] Add current-feature resolution and the initial implementation step to `.specify/workflows/execution/workflow.yml`, invoking `.specify/scripts/python/check_prerequisites.py --paths-only --json`, extracting `TASKS` with `from_json`, failing before implementation on resolver errors, and passing empty arguments to the first `speckit.implement` invocation
- [X] T007 [US1] Add the ordered success path to `.specify/workflows/execution/workflow.yml`, running `task lint` and then `task test:unit` as separate shell steps with `continue_on_error: true`, preventing unit tests after failed lint, and invoking `speckit.converge` only after both checks pass

**Checkpoint**: User Story 1 provides a runnable standalone workflow and can be verified manually with valid and invalid current-feature configurations.

---

## Phase 4: User Story 2 - Automatically remediate deterministic check failures (Priority: P1)

**Goal**: Return lint and unit-test failures to implementation with complete captured diagnostics as temporary feedback, then restart deterministic checks from lint.

**Independent Verification**: Run controlled local commands that make lint or unit tests fail, and verify the next implementation invocation receives the corresponding check name plus complete stdout and stderr, lint is rerun before unit tests, and diagnostics are not written to `tasks.md`.

### Implementation for User Story 2

- [X] T008 [US2] Extend `.specify/workflows/execution/workflow.yml` with lint-failure branching based on the shell step's `output.exit_code`, `output.stdout`, and `output.stderr`, passing complete untruncated lint diagnostics as temporary implementation feedback and restarting checks at lint
- [X] T009 [US2] Extend `.specify/workflows/execution/workflow.yml` with unit-failure branching that passes complete unit-test diagnostics as temporary implementation feedback, returns through implementation to lint, and never persists feedback in `tasks.md`

**Checkpoint**: User Story 2 closes deterministic lint/unit feedback loops without modifying feature artifacts with diagnostic output.

---

## Phase 5: User Story 3 - Close specification gaps through convergence (Priority: P1)

**Goal**: Compare the exact current feature `tasks.md` content immediately before and after convergence, repeat implementation only when convergence changes that file, and complete when it does not.

**Independent Verification**: Run the workflow once with convergence appending a task and once with convergence leaving `tasks.md` unchanged; verify that only the first case starts another implementation cycle and that unrelated pre-existing working-tree changes do not affect the decision.

### Implementation for User Story 3

- [X] T010 [US3] Add the pre-converge fingerprint step to `.specify/workflows/execution/workflow.yml`, hashing the resolver-provided `TASKS` path with `git hash-object` and exposing the object ID through a step output
- [X] T011 [US3] Add the post-converge fingerprint step and outer-loop condition to `.specify/workflows/execution/workflow.yml`, invoking `speckit.converge` without deterministic diagnostics and repeating only when the before/after object IDs differ
- [X] T012 [US3] Verify the complete workflow definition against `specs/020-execution-workflow/contracts/execution-workflow.yml.md` and `specs/020-execution-workflow/quickstart.md`, including resolver failures, unchanged fingerprints, changed fingerprints, and normal termination through built-in `max_iterations: 10`

**Checkpoint**: All three user stories are represented by one complete workflow and can be checked through the documented CLI scenarios.

---

## Phase 6: Polish & Cross-Cutting Concerns

**Purpose**: Validate the workflow and keep the implementation focused on the requested local execution loop.

- [X] T013 [P] Validate `.specify/workflows/execution/workflow.yml` and its installed registration with `specify workflow info .specify/workflows/execution/workflow.yml` and `specify workflow info execution`
- [X] T014 [P] Review `.specify/workflows/execution/workflow.yml` and `.specify/workflows/workflow-registry.json` for duplicated orchestration, diagnostic truncation, persisted diagnostics, an unintended `spec` input, or a project-specific retry counter; remove any violation found
- [X] T015 Confirm the final diff is limited to the execution workflow, synchronized registry metadata, and this feature's task plan; run `git diff --check -- .specify/workflows specs/020-execution-workflow/tasks.md`

---

## Dependencies & Execution Order

### Phase Dependencies

- **Setup (Phase 1)**: No dependencies; directory creation and runtime-convention inspection can start immediately.
- **Foundational (Phase 2)**: Depends on Setup; registry and runtime prerequisites block workflow implementation.
- **User Story 1 (Phase 3)**: Depends on Phase 2; provides the MVP success path.
- **User Story 2 (Phase 4)**: Depends on US1's workflow skeleton and step IDs; adds deterministic failure branches.
- **User Story 3 (Phase 5)**: Depends on US1's successful converge path and US2's loop semantics; adds fingerprint-based repetition.
- **Polish (Phase 6)**: Depends on all desired story work being complete.

### User Story Dependencies

- **US1 (P1)**: Depends only on Foundational.
- **US2 (P1)**: Depends on US1's implementation, lint, and unit step IDs.
- **US3 (P1)**: Depends on US1's successful checks/converge path and US2's remediation-safe control flow.

### Dependency Graph

```text
T001-T002 → T003-T004 → T005-T007 (US1)
                              ↓
                         T008-T009 (US2)
                              ↓
                         T010-T012 (US3)
                              ↓
                         T013-T015 (Polish)
```

### Parallel Opportunities

- **Setup**: T001 and T002 can run in parallel.
- **Foundation**: T003 and T004 can run in parallel after Setup.
- **US1**: T005-T007 modify the same workflow and should be applied sequentially.
- **US2**: T008 and T009 modify the same workflow and should be applied sequentially.
- **US3**: T010 and T011 modify the same workflow and should be applied sequentially; T012 follows both.
- **Polish**: T013 and T014 can run in parallel; T015 runs last.

### Parallel Example: User Story 1

```text
Task A: Confirm workflow schema conventions in .specify/workflows/speckit/workflow.yml
Task B: Confirm registry format in .specify/workflows/workflow-registry.json
Task C: Prepare the local source location .specify/workflows/execution/
```

### Parallel Example: User Story 2

```text
Task A: Review lint output fields and branch conditions against the workflow architecture
Task B: Review unit-test output fields and temporary-feedback constraints against the contract
```

### Parallel Example: User Story 3

```text
Task A: Review the before-converge git hash-object step and its output reference
Task B: Review the after-converge git hash-object step and outer-loop comparison
```

---

## Implementation Strategy

### MVP First (User Story 1 Only)

1. Complete Phase 1 and Phase 2.
2. Implement US1's standalone workflow and registry entry.
3. Validate with `specify workflow info` and the successful CLI scenario from `quickstart.md`.
4. Stop for an MVP demonstration before adding automatic remediation and convergence repetition.

### Incremental Delivery

1. Add US1: successful local execution loop and current-feature resolution.
2. Add US2: lint/unit failure feedback and deterministic retries.
3. Add US3: `tasks.md` fingerprint comparison and convergence-driven repetition.
4. Run the documented workflow-info and CLI validation scenarios.

### Notes

- Every task uses the required `- [ ] T###` checklist format.
- `[P]` is used only where work can proceed without editing the same file or depending on incomplete work.
- Story labels are present on every user-story task and absent from Setup, Foundational, and Polish tasks.
- No automated test files, fixtures, or test harness are planned for this feature.
