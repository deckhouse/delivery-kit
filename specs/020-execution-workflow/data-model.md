# Data Model: Local Execution Workflow

**Feature**: 020-execution-workflow

## Execution workflow

A versioned workflow definition identified by `execution`. It has no required feature-description input and runs against the feature selected in `.specify/feature.json`.

| Field | Type | Rules |
|---|---|---|
| `workflow.id` | string | Exactly `execution`. |
| `workflow.version` | string | Initial version `1.0.0`. |
| `inputs.integration` | string | Defaults to `auto`; explicit values are passed to AI command steps. |
| outer loop limit | positive integer | `max_iterations: 10`; uses the engine safeguard. |

## Current feature

The feature directory returned by `.specify/scripts/python/check_prerequisites.py --paths-only --json`.

| Field | Source | Rules |
|---|---|---|
| `FEATURE_DIR` | path resolver JSON | Must resolve before implementation or convergence. |
| `TASKS` | path resolver JSON | Absolute path to the current feature's `tasks.md`; used by fingerprint steps. |

A path-resolution failure is a workflow failure before the implementation/convergence sequence runs.

## Deterministic check result

The result of one shell invocation, retained in the workflow step result.

| Field | Type | Rules |
|---|---|---|
| `exit_code` | integer | `0` means pass; non-zero means remediation branch. |
| `stdout` | string | Preserve the complete captured standard output. |
| `stderr` | string | Preserve the complete captured standard error. |
| check name | literal | Either `lint` or `unit tests`; included in remediation feedback. |

Diagnostics are transient step output. They are never appended to `tasks.md`.

## Tasks fingerprint

The Git object ID returned by `git hash-object` for the resolved `tasks.md` at one point in the loop.

| Field | Type | Rules |
|---|---|---|
| path | absolute path | Obtained from the resolver JSON, not inferred from git state. |
| `object_id` | hexadecimal string | Output of `git hash-object` for the exact file bytes; the hash algorithm is the repository's Git configuration. |
| position | enum | `before-converge` or `after-converge`. |

The before/after comparison is scoped to the interval around `converge`; unrelated pre-existing working-tree changes do not affect it. Git is a mandatory prerequisite for the workflow.

## Execution state transitions

```text
created → running
running → implementation → lint
lint(pass) → unit tests
lint(fail) → implementation with lint feedback
unit tests(pass) → tasks fingerprint (before) → converge → tasks fingerprint (after)
unit tests(fail) → implementation with unit-test feedback → lint
fingerprints differ → implementation
fingerprints equal → completed
running → failed when current-feature path resolution fails or an unhandled step error occurs
```

The engine persists step results and run state after steps. The workflow does not add a project-specific retry state; the outer loop's built-in iteration safeguard terminates repeated cycles.
