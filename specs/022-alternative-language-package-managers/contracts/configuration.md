# Configuration Contract: Alternative Package Managers

## YAML schema

```yaml
packages:
  - type: javascript-yarn       # or javascript-pnpm, python-uv, python-poetry
    workdir: /app
    version: 1.22.22             # required; exact X.Y.Z
    spec: package.json           # optional ecosystem default
    lock: yarn.lock              # optional ecosystem default
    env:                          # optional, existing behavior
      NODE_ENV: production
```

Python example:

```yaml
packages:
  - type: python-poetry
    workdir: /app
    version: 2.1.3
```

## Validation

- `type` and `workdir` retain existing required-field validation.
- `version` is required for the four alternative types.
- `version` must match `^[0-9]+\.[0-9]+\.[0-9]+$`.
- `version` is rejected for `javascript-npm`, `python-pip`, `go-mod`, `rust-cargo`, `lua-rock`, and `os-pm`.
- Unknown YAML attributes remain rejected.
- Existing `spec`, `lock`, and `env` validation is unchanged.

## Command contract

Alternative-manager selection is defined by a switch helper over `PackagesDirectiveType`, with cases only for `javascript-yarn`, `javascript-pnpm`, `python-uv`, and `python-poetry`. `PackageEcosystem` does not contain an `isAlternativeManager` field.

A new internal command-wrapper type/factory centralizes the repeated `cd` and environment-prefix logic and returns an install-command function. For alternative types, the returned function creates an ephemeral scope, selects the isolated executable, and pairs it with cleanup:

1. fail if the manager executable is already present;
2. create the ecosystem-specific unique directive-local scope and install the exact manager there;
3. return and use the isolated absolute executable path for the existing frozen dependency command;
4. run the cleanup command returned by the command-wrapper factory only after dependency installation succeeds.

The cleanup command removes the directive-local scope (`npm uninstall --global --prefix <prefix> ...` followed by prefix removal, or removal of `<venv>`), not project dependencies. It is reached only after the dependency command succeeds. The temporary path is generated inside the command sequence and is not part of the deterministic checksum; manager version, isolation strategy, executable selection, dependency command, and cleanup semantics are. Each directive's version and workdir must affect its generated command and therefore its cache identity.

## Failure contract

Errors must identify bootstrap, exact-version resolution, dependency/lock installation, pre-existing manager, or cleanup as applicable. A dependency installation error must not be replaced by cleanup output because cleanup after a failed dependency install is not executed.
