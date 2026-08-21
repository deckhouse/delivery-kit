# Quickstart: Enforce a Single os-pm Directive

## Prerequisites

- Linux development environment with the repository dependencies installed.
- Run commands from the repository root.
- Use the project task commands for formatting, build, lint, and tests.

## Focused validation

1. Add or update co-located Ginkgo/Gomega tests in `pkg/config` covering:
   - zero `os-pm` entries;
   - exactly one `os-pm` entry;
   - two `os-pm` entries in both list orders;
   - multiple non-`os-pm` entries with one `os-pm` entry;
   - two `os-pm` entries with different package, workdir/spec/lock values.
2. Run the focused package tests:

   ```text
   task test:unit paths="./pkg/config/..."
   ```

3. Verify the invalid cases fail with an error containing `packages`, `os-pm`, and `only one` (or equivalent one-directive-limit wording), and that valid cases continue through package conversion.

## Broader validation

After implementation, run the required gates in order:

```text
task format
task build
task deps:install:golangci-lint
task lint
task test:unit
task test:e2e paths="./test/e2e/..." labelFilter="packages"
task test:integration
```

The e2e command is a scoped validation example; select the package/config label and path that cover the changed behavior if an existing suite is added. The invalid configuration must fail before package installation begins, while zero/one `os-pm` configurations and repeated other package types retain their prior behavior.

See [`data-model.md`](data-model.md) for cardinality and processing-state details and [`contracts/config-validation.md`](contracts/config-validation.md) for the user-visible error contract.
