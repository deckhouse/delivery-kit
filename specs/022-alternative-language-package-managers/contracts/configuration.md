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

A new internal command-wrapper type/factory centralizes the repeated `cd` and environment-prefix logic and returns an install-command function. For alternative types, the returned function emits one complete `if ... then ... else ... fi` block:

1. in the `then` branch, check whether the manager executable exists and fail with an explicit pre-installed-manager error if it does;
2. in the `else` branch, create the ecosystem-specific unique directive-local scope;
3. keep exact-version installation and verification, the frozen dependency command through its isolated absolute executable, and removal of only that scope after success on separate readable lines under fail-fast shell execution.

The cleanup command removes the directive-local scope (`npm uninstall --global --prefix <prefix> ...` followed by prefix removal, or removal of `<venv>`), not project dependencies. It is reached only after the dependency command succeeds. The temporary path is generated inside the command sequence and is not part of the deterministic checksum; manager version, isolation strategy, executable selection, dependency command, and cleanup semantics are. Each directive's version and workdir must affect its generated command and therefore its cache identity.

## Failure contract

Errors must identify pre-installed-manager rejection, bootstrap, exact-version resolution, dependency/lock installation, or cleanup as applicable. A dependency installation error must not be replaced by cleanup output because cleanup after a failed dependency install is not executed. Finding an existing alternative manager is an error for this feature version.
