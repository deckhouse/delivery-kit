# Implementation Plan: Local Execution Workflow

**Branch**: `020-execution-workflow` | **Date**: 2026-08-28 | **Spec**: [spec.md](spec.md)

**Input**: Feature specification from `/specs/020-execution-workflow/spec.md`

## Summary

Add a project-local Spec Kit workflow named `execution` that automates the Delivery Kit implementation loop: install the linter, implement, lint, unit tests, converge, and repeat when convergence changes the current feature's `tasks.md`. The workflow uses the existing command/shell/conditional/loop runtime described by the supplied Spec Kit `workflows/README.md` and `workflows/ARCHITECTURE.md`; standard Git `hash-object` commands compare the resolved tasks file without custom utilities.

## Technical Context

**Language/Version**: YAML workflow definition; existing Spec Kit workflow runtime; standard Git CLI; Go 1.24.10 remains the repository quality-gate target.

**Primary Dependencies**:
- Existing Spec Kit workflow engine and built-in `command`, `shell`, `if`, `while`, and `do-while` steps.
- `.specify/scripts/python/check_prerequisites.py` and its JSON path contract.
- Built-in workflow `from_json` filter for extracting `TASKS` from the resolver step output.
- Git CLI `git hash-object` for content fingerprints; no custom utility or new external dependency.
- Existing project tasks invoked by the workflow: `task deps:install:golangci-lint`, `task lint`, and `task test:unit`.

**Storage**: YAML source under `.specify/workflows/execution/`; workflow metadata in `.specify/workflows/workflow-registry.json`; current-feature state in `.specify/feature.json` and its resolved `tasks.md`; normal workflow run state under `.specify/workflows/runs/<run_id>/`.

**Validation**: Manual workflow smoke-run covering path resolution, ordering, failure feedback, Git fingerprint branching, and iteration limits. No automated tests are planned for this workflow-only feature.

**Target Platform**: Local terminal execution on the platforms supported by Spec Kit and the repository shell/task environment; no CI-specific behavior in this iteration.

**Project Type**: Project-local Spec Kit workflow stored in a Go CLI repository.

**Performance Goals**: Do not truncate diagnostics; fingerprint only the resolved `tasks.md`; avoid scanning unrelated working-tree files. One `git hash-object` invocation is sufficient per converge boundary.

**Constraints**: No `spec` input; integration defaults to `auto`; current-feature resolution must happen through the existing prerequisite script; `task test:unit` must not run after failed lint; diagnostic output is transient and must not be written to `tasks.md`; no project-specific retry counter; outer loop limit is the built-in `max_iterations: 10` safeguard.

**Scale/Scope**: One workflow definition, manual smoke-run documentation, and synchronized local workflow metadata. No automated tests, custom utility, workflow-engine changes, new CLI commands, Go production code, or external dependencies.

## Constitution Check

*GATE: evaluated against constitution v1.5.6 — PASS (pre-Phase-0 and re-checked post-Phase-1).* 

| Principle / boundary | Compliance |
|---|---|
| I. Simplicity Over Abstraction | PASS — compose existing workflow primitives and use the already-required Git CLI; add no helper or abstraction. |
| II. Go Idiomatic Code | N/A — no Go code or API changes. |
| III. Minimal Public Surface | PASS — exposes only the documented `execution` workflow and its existing CLI invocation; no new engine API or utility contract. |
| IV. Test-Before-Merge | N/A for this workflow-only change — no production Go code or automated test suite is added; behavior is validated by the documented manual smoke-run. |
| V. Conventional Commits | PASS — feature branch is `020-execution-workflow`; no commit is created by this plan. |
| Code Boundaries | PASS — workflow assets stay under `.specify/workflows/execution/`; no additional source or test tree is introduced. |
| Dependency Rules | PASS — existing Spec Kit runtime and Git CLI only; Git is an explicit workflow prerequisite and no external dependency is added. |
| Build & Quality Gates | PASS / N/A for Go gates — validate the YAML with Spec Kit workflow loading/info and run the installed workflow through the documented manual smoke-run; do not require Go build/lint/test commands or a Python virtualenv for this workflow-only feature. |

No constitution violations require complexity justification.

## Project Structure

### Documentation (this feature)

```text
specs/020-execution-workflow/
├── plan.md                         # This file
├── spec.md                         # Feature specification
├── research.md                     # Phase 0 decisions and alternatives
├── data-model.md                   # Workflow entities and state transitions
├── quickstart.md                   # Runnable validation guide
├── contracts/
│   └── execution-workflow.yml.md   # Workflow invocation and behavior contract
├── checklists/                     # Existing feature quality checklists
└── tasks.md                        # Phase 2 output; not created by plan
```

### Source Code (repository root)

```text
.specify/
├── feature.json                    # Existing current-feature selector
├── scripts/python/
│   └── check_prerequisites.py      # Existing canonical path resolver
└── workflows/
    ├── execution/
    │   └── workflow.yml                     # NEW: concise local execution loop definition
    └── workflow-registry.json               # Existing registry; keep execution metadata aligned
```

**Structure Decision**: Keep the feature at the workflow/configuration boundary. The workflow orchestrates existing Spec Kit runtime steps, installs the linter once before the loop, uses `from_json` to extract the resolver's `TASKS` value, and uses `git hash-object` for fingerprints. The YAML should express one compact do/while process and reuse step outputs rather than duplicate shell orchestration. No new utility, Go package, or workflow-engine step is justified.

## Phase 0: Research Summary

Research is complete in [research.md](research.md). Key decisions:

1. Compose the built-in runtime with an outer `do-while` and nested failure-remediation loops.
2. Use `integration: auto` and `.specify/feature.json` rather than a feature-description input.
3. Preserve shell `exit_code`, `stdout`, and `stderr` as step outputs and pass complete diagnostics only to implementation feedback.
4. Use the built-in `from_json` filter to extract `TASKS`; hash only that resolver-provided file before and after converge.
5. Use the built-in `max_iterations: 10` safeguard, with no custom retry counter.

## Phase 1: Design Summary

Design is complete in [data-model.md](data-model.md), [contracts/](contracts/), and [quickstart.md](quickstart.md). The implementation should:

- add the `execution` workflow YAML with explicit step IDs and branching;
- make lint failure branch immediately to implementation and restart at lint;
- make unit failure branch to implementation and restart at lint;
- keep unit tests behind a successful lint result;
- capture pre/post-converge fingerprints via step outputs and repeat only when they differ;
- install the linter once before entering the loop;
- keep resolver and Git fingerprint errors fatal before implementation/convergence;
- use one compact YAML loop with shared step outputs and no duplicated JSON parsing/orchestration;
- document and perform a manual smoke-run for Git fingerprinting and all execution branches; no automated tests are added.

## Implementation Notes for Phase 2

The task breakdown should preserve this dependency order:

1. Add the concise workflow definition with a single pre-loop linter-install step, `from_json` path extraction, `git hash-object` fingerprint steps, shared step outputs, and validate its schema, registration, input defaults, ordering, loop safeguards, and output references.
2. Verify the installed workflow metadata and perform the documented manual smoke-run for Git fingerprint isolation, complete diagnostics, lint/unit remediation, convergence branching, and path-resolution failure.

## Complexity Tracking

No constitution violations — table intentionally empty.
