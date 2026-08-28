# Phase 0 Research: Local Execution Workflow

**Feature**: 020-execution-workflow  
**Date**: 2026-08-28  
**Context**: `workflows/README.md` and `workflows/ARCHITECTURE.md` from the Spec Kit repository, plus the existing Delivery Kit Spec Kit installation.

## R1: Workflow composition

**Decision**: Implement `execution` as a declarative YAML workflow using the existing `command`, `shell`, `if`, `while`, and `do-while` step types. The outer `do-while` owns one or more complete implementation/check/converge cycles; nested `while` blocks remediate lint and unit failures.

**Rationale**: The architecture documents control-flow steps as the intended extension point and says nested steps share `StepContext` and `RunState`. A do-while guarantees the first implementation pass, while a fingerprint comparison controls subsequent passes without introducing application-specific state.

**Alternatives considered**:
- A new Python or Go workflow step — rejected because the required behavior is expressible with built-in steps and would expand the runtime surface.
- A shell-only orchestration script — rejected because it would bypass persisted step results, standard workflow status/resume behavior, and expression-based branching.
- A separate project-wide utility directory — rejected because the helper is specific to this workflow and should be installed, moved, and tested with the workflow definition.

## R2: Integration selection and current feature

**Decision**: Declare an `integration` string input with default `auto`, pass it to `speckit.implement` and `speckit.converge`, and omit a `spec` input. The workflow relies on the existing engine's `auto` integration resolution and the project-level `.specify/feature.json` selected feature.

**Rationale**: The built-in `speckit` workflow establishes the integration input pattern. The feature specification explicitly requires no description input and requires operation on the current feature. `check_prerequisites.py --paths-only --json` is the existing canonical resolver.

**Alternatives considered**:
- Passing a feature description to implement/converge — rejected; this feature operates on persisted feature artifacts.
- Resolving feature paths from shell environment state — rejected; the architecture supports step outputs and the prerequisite script provides the authoritative path.

## R3: Deterministic failure feedback

**Decision**: Run `task lint` and `task test:unit` as separate shell steps with `continue_on_error: true`. Branch on each step's `output.exit_code`; construct the next implementation prompt from the failed check name plus the complete `stdout` and `stderr` outputs.

**Rationale**: The workflow README documents that returned failures retain `exit_code` and that downstream `if` steps can branch on it. It also distinguishes returned failures from unhandled exceptions, so the workflow must use the shell step's normal failure result. No workflow-level truncation is added, and feedback is supplied through command input rather than written to feature files.

**Alternatives considered**:
- Running unit tests even when lint fails — rejected by FR-005 and the clarified execution order.
- Persisting diagnostics in `tasks.md` — rejected because diagnostics are temporary implementation feedback, not feature work.
- Adding a separate retry counter — rejected; the built-in loop safeguard is the required limit mechanism.

## R4: Tasks fingerprint and JSON handling

**Decision**: Do not add a fingerprint helper. The workflow invokes `.specify/scripts/python/check_prerequisites.py --paths-only --json` and uses the built-in `from_json` filter to extract `TASKS` from that step's `stdout`, then runs `git hash-object` directly on that path before and after `converge`.

**Rationale**: The prerequisite script remains the canonical current-feature resolver, while the architecture explicitly supports `from_json` for typed extraction from step output. Git is a mandatory dependency for this local workflow, so `git hash-object` provides content identity without custom code. Hashing only `tasks.md` avoids treating unrelated working-tree changes as workflow changes.

**Alternatives considered**:
- Parsing resolver JSON in a custom helper — rejected because the workflow engine already provides `from_json`.
- A custom Python/Go fingerprint utility — rejected because `git hash-object` is sufficient and Git is mandatory.
- `git diff` or repository status — rejected because unrelated uncommitted changes must not influence the decision.
- Hashing the whole feature directory — rejected because only `tasks.md` changes should trigger another implementation pass.
- Sharing shell environment variables across steps — rejected; the architecture explicitly exposes step outputs as the supported state-passing mechanism.

## R5: Workflow source and installation

**Decision**: Store the source definition at `.specify/workflows/execution/workflow.yml` and keep the installed registry entry synchronized with identifier `execution`, version `1.0.0`, and the local source path. No workflow-specific utility directory or automated test suite is needed; validation uses direct file loading and an installed-ID smoke-run.

**Rationale**: The architecture defines `.specify/workflows/{id}/workflow.yml` and `workflow-registry.json` as the project-local locations for definitions and metadata. The existing registry already contains the expected execution metadata, so the source file is the missing implementation artifact rather than a new catalog mechanism. Standard Git commands keep the implementation self-contained in YAML, and a manual smoke-run is sufficient for this workflow-only change.

**Alternatives considered**:
- Add the workflow only to the global catalog — rejected; this is a Delivery Kit project-local workflow.
- Modify the workflow engine — rejected; no engine limitation is identified by the requirements or supplied architecture.

## R6: Safety and iteration semantics

**Decision**: Use `max_iterations: 10` on the outer loop and rely on the engine's normal loop-limit behavior. A limit hit ends the loop normally; it is not translated into a project-specific retry failure. On a nested pause/resume, accept the documented engine behavior that the parent control-flow step may rerun its nested body.

**Rationale**: The feature clarification explicitly selects the built-in safeguard. The architecture documents top-level resume tracking and nested-step rerun semantics, which should be reflected in validation expectations rather than worked around with custom state.

**Alternatives considered**:
- Add a `retry_count` input or file — rejected by FR-014 and would create feature-specific state outside the workflow engine.
- Increase or disable the engine limit — rejected because indefinite local automation is unsafe.
