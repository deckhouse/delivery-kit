# Contract: `execution` workflow definition

**Source**: `.specify/workflows/execution/workflow.yml`

## Invocation

```sh
specify workflow run execution
specify workflow run execution -i integration=claude
```

The workflow accepts only the optional `integration` input for this feature. Its default is `auto`. The current feature is resolved from `.specify/feature.json`; no `spec` input is required.

## Required step behavior

The definition MUST contain one concise process with this logical sequence:

1. Install the linter once before entering the loop.
2. In a `do-while` loop, resolve current-feature paths with `.specify/scripts/python/check_prerequisites.py --paths-only --json`, then extract `TASKS` with the built-in `from_json` filter.
3. Invoke `speckit.implement` with empty arguments on the initial pass, or with the previous failed check's complete diagnostics on a remediation pass.
4. Run `task lint` as a separate shell step with failure continuation enabled; if it exits non-zero, branch back to `implement` and then restart the loop's checks at lint.
5. Run `task test:unit` only after lint succeeds; if it exits non-zero, branch back to `implement` and restart checks at lint.
6. Capture the tasks fingerprint immediately before `speckit.converge`, invoke converge without deterministic diagnostics, and capture the fingerprint immediately after it.
7. Continue the outer loop when fingerprints differ and finish when they are equal.

The YAML SHOULD reuse the loop's shared step outputs and use expressions to branch, rather than duplicate equivalent shell blocks. The outer repetition MUST use the built-in `do-while`/`max_iterations` mechanism with limit `10`, not a workflow-specific retry counter.

## Observable outputs

- A valid current feature starts and produces persisted step results.
- Path resolution failure stops the run before implementation and converge.
- Failed checks expose `exit_code`, `stdout`, and `stderr`; all diagnostic bytes are included in remediation input.
- The converge decision is based only on the two `tasks.md` fingerprints.
- No diagnostic text is written to `tasks.md` by the workflow.
- The workflow is validated by manual smoke-runs; no automated test contract is required.
