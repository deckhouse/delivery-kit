# Quickstart: validate the PM_LOCK_FILE restriction

## Prerequisites

- Repository dependencies and the prepared test environment are available.
- Run commands from the repository root.

## Validation scenarios

1. Run the focused configuration unit tests:

   ```sh
   task test:unit paths="./pkg/config/..." -- -focus="PM_LOCK_FILE|os-pm"
   ```

   Expected result: tests reject custom, default-path, and empty `PM_LOCK_FILE` values; accept `os-pm` without that key; and preserve unrelated variables and non-`os-pm` directives.

2. Run the broader configuration unit suite:

   ```sh
   task test:unit paths="./pkg/config/..."
   ```

   Expected result: existing package directive parsing and validation remain green.

3. Verify the fixed SBOM source path in the metadata and collector tests:

   ```sh
   task test:unit paths="./pkg/sbom/os_pm/..."
   ```

   Expected result: the collector continues reading `/var/lib/pm/index.json`; no accepted configuration can override it through `PM_LOCK_FILE`.

4. Before handoff, run the repository-required gates for the implementation: `task format`, `task build`, `task deps:install:golangci-lint`, `task lint`, `task test:unit`, a scoped SBOM/configuration e2e command with `paths` and `labelFilter`, and `task test:integration`.

See [configuration contract](contracts/configuration.md) and [data model](data-model.md) for the user-facing rule and validation boundary.
