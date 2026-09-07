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

`PackageEcosystem` exposes two callback fields beside `InstallCmd`:

```go
InstallAlternativeManagerCmd func(workdir string, files FileBasedSpec, env map[string]string) string
CleanupAlternativeManagerCmd  func(workdir string, files FileBasedSpec, env map[string]string) string
```

For each alternative type, `InstallCmd` calls these callbacks to generate one ordered command sequence:

1. fail if the manager executable is already present;
2. install the exact manager package globally through npm or pip (`npm install --global ...`; for pip, install into the system interpreter without `--user` or a virtual environment);
3. run the existing frozen dependency command through the global executable;
4. remove only the temporary global manager installation.

The cleanup callback is reached only after the dependency command succeeds and removes the globally installed manager package (`npm uninstall --global ...` or the corresponding system-interpreter `pip uninstall`), not project dependencies. Commands are part of the package-stage checksum. Each directive's version and workdir must affect its generated command and therefore its cache identity.

## Failure contract

Errors must identify bootstrap, exact-version resolution, dependency/lock installation, pre-existing manager, or cleanup as applicable. A dependency installation error must not be replaced by cleanup output because cleanup after a failed dependency install is not executed.
