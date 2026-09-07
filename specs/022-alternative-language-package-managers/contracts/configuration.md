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

For each alternative directive, generated commands must execute in this order:

1. fail if the manager executable is already present;
2. install the exact manager package through npm or pip;
3. run the existing frozen dependency command;
4. remove only the temporary manager installation.

Commands are part of the package-stage checksum. Each directive's version and workdir must affect its generated command and therefore its cache identity.

## Failure contract

Errors must identify bootstrap, exact-version resolution, dependency/lock installation, pre-existing manager, or cleanup as applicable. A dependency installation error must not be replaced by cleanup output because cleanup after a failed dependency install is not executed.
