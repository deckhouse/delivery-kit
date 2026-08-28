# Quickstart: Validate the Local Execution Workflow

**Feature**: 020-execution-workflow  
**Contract**: [execution-workflow.yml.md](contracts/execution-workflow.yml.md)

## Prerequisites

- Work from the Delivery Kit repository root.
- A valid `.specify/feature.json` pointing to a feature with `spec.md`, `plan.md`, and `tasks.md`.
- The project’s selected Spec Kit integration provides `speckit.implement` and `speckit.converge`.
- The standard `task lint` and `task test:unit` commands are available.

## Fingerprint validation

The workflow resolves the current feature and extracts its tasks path without a custom JSON parser:

```text
{{ steps.resolve_paths.output.stdout | from_json }}
```

The workflow passes the extracted `TASKS` value to `git hash-object` before and after `converge`:

```sh
git hash-object /absolute/path/to/tasks.md
```

Expected result: the same Git object ID when `tasks.md` is unchanged and a different object ID when its bytes change. Change an unrelated file and verify that the object ID is unaffected. Git is a mandatory prerequisite for this local workflow.

Malformed resolver JSON or a missing `TASKS` field must fail in the workflow's `from_json` expression. A missing/unreadable target must make the `git hash-object` shell step fail before the implementation/convergence decision can continue.

## Workflow scenarios

Start the installed workflow:

```sh
specify workflow run execution
```

Override the integration:

```sh
specify workflow run execution -i integration=claude
```

Verify status and persisted results when needed:

```sh
specify workflow status
specify workflow status <run_id>
```

Expected behavior:

1. The workflow resolves the current feature before invoking implementation.
2. The first `implement` receives empty arguments.
3. Lint runs before unit tests.
4. A lint failure sends the complete lint stdout/stderr and the label `lint` to a new implementation pass, then restarts at lint.
5. A unit-test failure sends the complete unit stdout/stderr and the label `unit tests` to implementation, then restarts at lint.
6. Passing checks run converge with no check diagnostics as extra input.
7. A changed tasks fingerprint starts another implementation cycle; an unchanged fingerprint completes the workflow.
8. Repeated cycles stop through `max_iterations: 10`, without a project-specific retry failure.

## Validation

Validate the workflow definition and its installed registration:

```sh
specify workflow info .specify/workflows/execution/workflow.yml
specify workflow info execution
```

Run the workflow from a controlled current-feature fixture:

```sh
specify workflow run execution
```

Cover these scenarios during a manual smoke-run with a valid current feature and controlled command outcomes:

- Git object ID stays equal when only unrelated files change and differs when `tasks.md` changes;
- the linter installation runs once before the loop;
- the initial implementation receives empty arguments;
- lint and unit failures preserve complete diagnostics and return to implementation in the required order;
- converge repeats only when the before/after Git object IDs differ;
- invalid feature resolution stops before implementation and converge;
- the built-in `max_iterations: 10` limit ends repeated cycles without a project-specific retry failure.

No automated tests, Go build/lint/unit-test/e2e/integration commands, or Python virtualenv are required to validate this workflow-only feature. The YAML must keep the linter installation outside the loop and avoid duplicated lint/unit/converge orchestration.
