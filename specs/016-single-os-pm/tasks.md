---

description: "Actionable task list for enforcing a single os-pm directive"
---

# Tasks: Enforce a Single os-pm Directive

**Input**: Design documents from `specs/016-single-os-pm/`

**Prerequisites**: `plan.md`, `spec.md`, `research.md`, `data-model.md`, `contracts/config-validation.md`, and `quickstart.md`

**Tests**: Included because the specification and quickstart require co-located Ginkgo/Gomega coverage.

## Phase 1: Setup (Existing Project Context)

**Purpose**: Confirm the existing brownfield boundaries before implementation; no project initialization or dependency changes are required.

- [X] T001 [P] Confirm the implementation boundary and existing test harness in `pkg/config/raw_stapel_image.go`, `pkg/config/raw_packages_directive.go`, `pkg/config/raw_stapel_image_test.go`, and `pkg/config/config_suite_test.go`

---

## Phase 2: Foundational (Shared Validation Contract)

**Purpose**: Establish the shared behavior that both user stories rely on before story-specific work begins.

- [X] T002 Record the list-level validation and compatibility matrix from `specs/016-single-os-pm/contracts/config-validation.md` in the test cases planned for `pkg/config/raw_stapel_image_test.go`

**Checkpoint**: The target conversion boundary, existing detailed-error mechanism, and unchanged lower-level command-generation contract are identified.

---

## Phase 3: User Story 1 - Reject multiple os-pm directives (Priority: P1) 🎯 MVP

**Goal**: Reject an image configuration when its raw `packages` list contains two or more entries with `type: os-pm`, while preserving zero/one `os-pm` and repeated non-`os-pm` behavior.

**Independent Test**: Convert configurations with zero, one, and multiple `os-pm` entries through the raw image conversion path and verify that only the multiple-entry cases fail before package commands are generated.

### Tests for User Story 1

- [X] T003 [US1] Add co-located Ginkgo/Gomega table coverage in `pkg/config/raw_stapel_image_test.go` for zero `os-pm`, exactly one `os-pm`, two `os-pm` entries in both list orders, multiple non-`os-pm` entries with one `os-pm`, and distinct `package`, `workdir`, `spec`, and `lock` values

### Implementation for User Story 1

- [X] T004 [US1] Add an O(n) raw-type count and early configuration failure in `pkg/config/raw_stapel_image.go` before `rawPackagesDirective.toDirective` conversion and before `GeneratePackagesCommands`

- [X] T005 [US1] Verify in `pkg/config/packages_commands_test.go` and `pkg/config/packages_commands.go` that lower-level `GeneratePackagesCommands` behavior remains unchanged for direct callers, including one command per supplied directive

**Checkpoint**: User Story 1 is independently testable, rejects every invalid cardinality case before build processing, and preserves valid and non-`os-pm` configurations.

---

## Phase 4: User Story 2 - Identify the configuration error clearly (Priority: P2)

**Goal**: Make the multiplicity failure actionable by naming `packages`, `os-pm`, and the one-directive limit while retaining rendered source-document context.

**Independent Test**: Convert an invalid configuration with multiple `os-pm` entries and assert that the returned error contains the required diagnostic terms and source context, regardless of directive values or order.

### Tests for User Story 2

- [X] T006 [US2] Add focused diagnostic assertions in `pkg/config/raw_stapel_image_test.go` that the multiple-`os-pm` error identifies `packages`, names `os-pm`, states that only one directive is allowed or equivalent, and includes the rendered configuration document context

### Implementation for User Story 2

- [X] T007 [US2] Use `newDetailedConfigError` with the existing raw image document in `pkg/config/raw_stapel_image.go` so the cardinality failure provides the required actionable message and source context

**Checkpoint**: User Story 2 is independently testable through the configuration conversion path and provides a correction-oriented diagnostic without changing valid behavior.

---

## Phase 5: Polish & Cross-Cutting Validation

**Purpose**: Apply repository formatting and run the required build, lint, unit, e2e, and integration gates for the changed configuration behavior.

- [X] T008 [P] Format the changed Go files `pkg/config/raw_stapel_image.go` and `pkg/config/raw_stapel_image_test.go` with `task format`

- [X] T009 Build the repository after the `pkg/config` change with `task build`

- [X] T010 Install the session lint prerequisite before checking `pkg/config/` with `task deps:install:golangci-lint`

- [X] T011 Run repository linting with `task lint` against the implementation and tests in `pkg/config/`

- [X] T012 Run focused unit coverage with `task test:unit paths="./pkg/config/..."` for `pkg/config/raw_stapel_image.go`, `pkg/config/raw_stapel_image_test.go`, and `pkg/config/packages_commands_test.go`

- [X] T013 Run the applicable scoped e2e coverage with `task test:e2e paths="./test/e2e/..." labelFilter="packages"` and confirm no existing package/config suite is regressed

- [ ] T014 Run the full integration gate for the `pkg/config/` behavior with `task test:integration` to verify invalid configurations fail before package installation and valid configurations retain prior behavior

---

## Dependencies & Execution Order

### Phase Dependencies

- **Setup (Phase 1)**: No dependencies; confirms the existing implementation boundary.
- **Foundational (Phase 2)**: Depends on Setup; establishes the shared behavior matrix.
- **User Story 1 (Phase 3)**: Depends on the foundational contract; delivers the MVP validation behavior.
- **User Story 2 (Phase 4)**: Depends on User Story 1 because it verifies and completes the error produced by that validation path.
- **Polish (Phase 5)**: Depends on the implemented stories; runs formatting and repository quality gates.

### User Story Dependencies

- **User Story 1 (P1)**: Can start after Phase 2; no dependency on other user stories.
- **User Story 2 (P2)**: Depends on User Story 1's cardinality failure path, but is independently testable through configuration conversion once that path exists.

### Within Each User Story

- Write the story's tests before implementation and ensure invalid cases fail before the implementation is added.
- Keep list-level cardinality validation in `pkg/config/raw_stapel_image.go`.
- Do not change the lower-level `GeneratePackagesCommands` API or its direct-call behavior.
- Complete the story's independent test criteria before moving to the next priority.

### Parallel Opportunities

- T001 and T002 can be prepared in parallel because they are analysis/contract tasks with no implementation dependency.
- After T004, T005 can be reviewed or validated independently from the diagnostic work in User Story 2.
- T008 through T011 can be scheduled as separate quality-gate activities after implementation, although formatting should complete before build/lint.
- No story phases are fully independent in this feature because User Story 2 intentionally validates the error path introduced for User Story 1.

---

## Parallel Example: User Story 1

```text
Task: Prepare the cardinality/compatibility matrix for pkg/config/raw_stapel_image_test.go (T002)
Task: Review the existing raw conversion and Ginkgo suite in pkg/config/raw_stapel_image.go and pkg/config/raw_stapel_image_test.go (T001)
```

After the shared boundary is confirmed:

```text
Task: Add the US1 table cases in pkg/config/raw_stapel_image_test.go (T003)
Task: Review unchanged direct command-generation behavior in pkg/config/packages_commands.go and pkg/config/packages_commands_test.go (T005)
```

These tasks touch different concerns, but T004 must complete before the new invalid-case tests can pass.

---

## Implementation Strategy

### MVP First (User Story 1 Only)

1. Complete T001-T002 to confirm the existing conversion boundary and behavior matrix.
2. Add T003 and implement T004.
3. Complete T005 to verify the lower-level command-generation contract is preserved.
4. Run T008 and T012 for focused validation.
5. Stop at the User Story 1 checkpoint if only the core nondeterminism safeguard is needed.

### Incremental Delivery

1. Deliver User Story 1: reject multiple `os-pm` directives while preserving valid configurations.
2. Deliver User Story 2: make the failure diagnostic actionable and source-aware.
3. Complete the Phase 5 repository gates before handoff.

### Scope Constraints

- Do not add dependencies, public APIs, CLI commands, generated files, or documentation changes.
- Do not alter `GeneratePackagesCommands` to reject direct lower-level inputs; the restriction applies at configuration validation time.

---

## Notes

- Every task uses the required `- [ ] [TaskID] [P?] [Story?]` checklist structure.
- Story tasks carry `[US1]` or `[US2]`; Setup, Foundational, and Polish tasks intentionally omit story labels.
- Tests are co-located and use the repository's Ginkgo/Gomega conventions.
