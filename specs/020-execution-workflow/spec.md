# Feature Specification: Local Execution Workflow

**Feature Branch**: `020-execution-workflow`

**Created**: 2026-08-27

**Status**: Draft

**Input**: User description: "Create a standalone spec-kit workflow for the local Execution Loop: implement, lint, all unit, converge, and repeat implementation when checks fail or converge appends tasks."

## Project Context

**Delivery Kit** is a Go CLI tool for full-cycle CI/CD to Kubernetes. This feature extends the repository's Spec-Driven Development workflow so an engineer can execute the implementation loop locally from a terminal.

## Clarifications

### Session 2026-08-27

- Q: What should happen if implementation, lint, or unit tests keep failing indefinitely? → A: Use the built-in Spec Kit loop safeguard (`max_iterations`, default 10) without adding a project-specific retry counter.
- Q: If `task lint` fails, should the workflow rerun `implement` before running `task test:unit`, and only run unit tests after lint passes? → A: Retry `implement` immediately, restart checks from lint, and run unit tests only after lint passes.
- Q: If `task test:unit` fails, should the workflow rerun `implement` and then restart deterministic checks from `task lint`? → A: Retry `implement` with the unit-test diagnostics, then rerun lint followed by unit tests.
- Q: Should deterministic check feedback preserve all captured stdout and stderr, even when the combined output is very large? → A: Preserve and pass all captured stdout and stderr without workflow-level truncation.

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Run the local execution loop (Priority: P1)

As a developer working on a feature in Delivery Kit, I want to start a standalone execution workflow from the terminal so that implementation and project verification proceed as one repeatable process instead of requiring manual skill-by-skill orchestration.

**Why this priority**: Automating the local implementation loop is the primary outcome of this feature.

**Independent Test**: With a current feature selected in `.specify/feature.json`, run `specify workflow run execution` and verify that the workflow invokes implementation, lint, unit tests, and convergence in the defined order.

**Acceptance Scenarios**:

1. **Given** a valid current feature and the default project integration, **When** the user runs `specify workflow run execution`, **Then** the standalone `execution` workflow starts without requiring a feature description input.
2. **Given** a valid current feature and an explicit integration, **When** the user runs `specify workflow run execution -i integration=claude`, **Then** the workflow uses the selected integration for its AI command steps.
3. **Given** the current feature context cannot be resolved, **When** the user starts the workflow, **Then** the workflow fails with the path-resolution error and does not run implementation or convergence steps.

---

### User Story 2 - Automatically remediate deterministic check failures (Priority: P1)

As a developer, I want lint and unit-test failures to return control to implementation with their diagnostics so that the agent can correct the code and rerun the checks automatically.

**Why this priority**: Without feedback-driven retries, the workflow only chains commands and does not close the implementation loop.

**Independent Test**: Cause a lint or unit-test command to fail, run the workflow, and verify that the next implementation invocation receives the failed check's complete diagnostic output before the check is retried.

**Acceptance Scenarios**:

1. **Given** `task lint` fails, **When** the workflow evaluates the lint step, **Then** it invokes `implement` again with a message identifying lint and containing the complete lint stdout and stderr.
2. **Given** `task test:unit` fails, **When** the workflow evaluates the unit step, **Then** it invokes `implement` again with a message identifying unit tests and containing the complete unit-test stdout and stderr.
3. **Given** both deterministic checks pass, **When** the workflow proceeds, **Then** it invokes `converge` rather than returning to implementation because of a deterministic failure.
4. **Given** deterministic check diagnostics are passed to implementation, **When** the implementation loop continues, **Then** those diagnostics remain temporary feedback and are not written to `tasks.md`.

---

### User Story 3 - Close specification gaps through convergence (Priority: P1)

As a developer, I want convergence to add newly discovered work to the current feature's task list and cause another implementation pass when necessary, while allowing the workflow to finish when no new work is found.

**Why this priority**: Convergence is the non-deterministic gate that ensures the implementation satisfies the feature artifacts rather than merely passing automated checks.

**Independent Test**: Run the workflow once with a converge pass that appends tasks and once with a converge pass that leaves `tasks.md` unchanged; verify that the first case repeats implementation and the second case completes.

**Acceptance Scenarios**:

1. **Given** `implement`, lint, and unit tests have completed successfully, **When** `converge` appends tasks to the current feature's `tasks.md`, **Then** the workflow detects the changed fingerprint and starts another implementation pass.
2. **Given** `implement`, lint, and unit tests have completed successfully, **When** `converge` leaves `tasks.md` unchanged, **Then** the workflow completes successfully.
3. **Given** the current `tasks.md` already has unrelated uncommitted changes, **When** the workflow runs converge, **Then** only changes made between the before-converge and after-converge fingerprints determine whether another implementation pass is required.

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: The repository MUST provide a standalone spec-kit workflow with the identifier `execution`.
- **FR-002**: The workflow MUST operate on the current feature resolved from `.specify/feature.json` and MUST NOT require a `spec` input.
- **FR-003**: The workflow MUST provide an `integration` input with default value `auto` and allow the user to override it at workflow start.
- **FR-004**: Each execution loop MUST invoke `implement` before invoking deterministic checks.
- **FR-005**: The workflow MUST run `task lint` and `task test:unit` as separate deterministic steps after implementation, in that order. The workflow MUST run `task test:unit` only after `task lint` passes.
- **FR-006**: If `task lint` fails, the workflow MUST immediately return to `implement`, provide all captured lint stdout and stderr without workflow-level truncation as temporary feedback, and restart deterministic checks from `task lint` after implementation.
- **FR-007**: If `task test:unit` fails, the workflow MUST immediately return to `implement`, provide all captured unit-test stdout and stderr without workflow-level truncation as temporary feedback, and restart deterministic checks from `task lint` after implementation.
- **FR-008**: Deterministic check diagnostics MUST NOT be appended to or otherwise persisted in `tasks.md`.
- **FR-009**: Before `converge`, the workflow MUST obtain the path to the current feature's `tasks.md` using the existing Spec Kit path-resolution script `.specify/scripts/python/check_prerequisites.py --paths-only --json`.
- **FR-010**: The repository MUST provide a project script under `scripts/specify` that parses the path-resolution script's JSON output and returns a fingerprint for the resolved `tasks.md`.
- **FR-011**: The workflow MUST capture a `tasks.md` fingerprint before `converge` and another after `converge` using outputs of workflow steps.
- **FR-012**: If the before- and after-converge fingerprints differ, the workflow MUST return to `implement` without passing converge output as additional feedback.
- **FR-013**: If the before- and after-converge fingerprints are equal, the workflow MUST complete successfully.
- **FR-014**: The workflow MUST use the built-in Spec Kit loop safeguard for repeated iterations (`max_iterations`, default 10) and branching constructs rather than a project-specific retry counter. Reaching the built-in iteration limit MUST stop the loop normally and MUST NOT be represented as a project-specific retry failure.
- **FR-015**: The initial implementation invocation MUST receive empty arguments; an implementation invocation caused by a deterministic failure MUST receive a message naming the failed check and containing its complete output.

### Key Entities

- **Execution workflow**: The standalone workflow definition that coordinates implementation, deterministic checks, and convergence.
- **Current feature**: The feature directory resolved from `.specify/feature.json`.
- **Tasks fingerprint**: The SHA-256 digest of the current feature's `tasks.md` content at a specific point in the workflow.
- **Deterministic check result**: The captured exit code and stdout/stderr produced by `task lint` or `task test:unit`.
- **Temporary implementation feedback**: Diagnostic text passed to a subsequent `implement` invocation without being persisted in feature artifacts.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: A developer can start the local execution workflow with `specify workflow run execution` without supplying a feature description, provided `.specify/feature.json` points to a valid feature.
- **SC-002**: In 100% of deterministic failure cases, the next implementation invocation receives the corresponding check name and complete captured diagnostics.
- **SC-003**: In 100% of converge passes that append tasks, the workflow starts another implementation invocation; in 100% of converge passes that do not modify `tasks.md`, the workflow completes.
- **SC-004**: The workflow keeps deterministic diagnostics out of `tasks.md` in every execution path.
- **SC-005**: The workflow uses no project-specific retry counter while implementing the initial loop.

## Assumptions

- The repository is a Spec Kit project with `.specify/feature.json` and the existing Python path-resolution scripts available.
- The current feature's `tasks.md` exists before `converge` is invoked; missing prerequisites are reported by the existing Spec Kit commands.
- The selected integration provides the `speckit.implement` and `speckit.converge` commands.
- `converge` is append-only for `tasks.md`: it either leaves the file unchanged or appends new tasks.
- A non-zero exit code from either deterministic shell step is a failure requiring another implementation pass.
- The initial version is intended for local terminal execution; CI execution and a five-attempt limit are out of scope for this iteration.
- Workflow step outputs are the supported mechanism for passing fingerprints and diagnostics between steps; shell environment changes are not relied upon across steps.
