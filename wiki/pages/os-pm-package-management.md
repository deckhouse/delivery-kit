---
title: OS Package Management (os-pm) in werf
type: concept
sources: [S003, S015, S018]
updated: 2026-08-07
---

OS-level packages in werf are declared inline in `werf.yaml` using the `os-pm` type, which installs packages via the `pm` tool during the build phase (S003). For the general file-based package ecosystem registry pattern, see [Package ecosystem registry](./package-ecosystem-registry.md).

## Inline syntax (deprecated)

The original `os-pm` syntax used an inline list of package names in `werf.yaml`:

```yaml
packages:
  - type: os-pm
    spec:
      - curl==8.12.1
      - jq
```

This syntax was **deprecated** in S018 in favour of the file-based syntax below (S018).

## File-based syntax (current)

`os-pm` now uses the same file-based spec+lock model as language package types. Packages are declared in a `pm.yaml` spec file, locked via `pm lock` (run outside werf), and committed alongside `pm.lock`. In `werf.yaml` the `os-pm` directive uses:

```yaml
packages:
  - type: os-pm
    # spec: pm.yaml (default)
    # lock: pm.lock (default)
```

The `spec` field is a string (file path relative to repository root), consistent with all other file-based package types. The `lock` field defaults to `pm.lock`. The `workdir` field is NOT configurable for `os-pm` — specifying it produces a validation error (S018).

Custom paths are supported:

```yaml
packages:
  - type: os-pm
    spec: custom-pm.yaml
    lock: custom.lock
```

The generated install command is `pm sync --from <lockfile>` (replacing the old `pm install <pkgs>`). Environment variables (`PACKAGES_VERSION`, `REGISTRY`) and user-defined env vars are passed as inline prefixes before the command (S018).

## Stage dependencies

Users configure `git.stageDependencies.packages` to trigger packages stage invalidation when `pm.yaml` or `pm.lock` change:

```yaml
git:
  - stageDependencies:
      packages:
        - pm.yaml
        - pm.lock
```

This is a user-side configuration — the system already supports `stageDependencies.packages` for all package types (S018).

## Unified PackageEcosystem registry

The `PackageEcosystem` struct in `pkg/config/` uses a single unified `InstallCmd` signature that works for all ecosystem types:

```go
InstallCmd func(workdir, specFile string, specList []string) string
```

- File-based ecosystems (go-mod, python-uv, etc.) use `workdir` and `specFile`; `specList` is nil.
- Inline-package-list ecosystems (os-pm) use `specList`; `workdir` and `specFile` are empty.
- Each ecosystem's `InstallCmd` encapsulates ALL logic: environment setup, install command, and SBOM state capture (S003).

This eliminated the need for separate `SkipWorkdir`, `SkipSpec`, `SkipLock`, and `PackagesInstallCmd` fields that were present in the previous design. `GeneratePackagesCommands()` now calls `eco.InstallCmd()` uniformly for all types — no special-casing (S003). The `os-pm` type uses the same `FileBasedSpec` resolution path as other package types, with the key difference that `workdir` is always empty (S018).

## PM BOMPatcher

After the SBOM is generated from `pm.lock`, a `PMBOMPatcher` in `pkg/sbom/packages/os_pm/pm_bom_patcher.go` post-processes the merged BOM to append the `containerFactoryVersion` PURL qualifier to each PM component's PURL. This version only exists inside the built image (`/var/lib/pm/container-factory-version`), so it cannot be read from the build context alone. The patcher matches PM components via `syft:package:foundBy = "os-pm-lock-cataloger"` (S018).

## Paradigm difference (was)

The file-based spec+lock model (pm.yaml/pm.lock) was previously considered a misfit for OS-level package managers because they were thought not to enforce determinism the way language-specific package managers do. However, the `pm` tool has since evolved to support deterministic lock files via `pm lock` and `pm sync --from`, making the file-based syntax the appropriate and only supported model (S018).

## Environment variable support

werf.yaml supports an optional `env` field on any `packages[]` entry. It is accepted for all package types in the config schema, but runtime behavior is only implemented for `os-pm` (S015). For other types, the field is silently ignored.

```yaml
packages:
  - type: os-pm
    spec:
      - curl
    env:
      DOCKER_CONFIG: /run/secrets/config.json
      HTTP_PROXY: http://proxy.example.com:8080
      DEBIAN_FRONTEND: noninteractive
```

The environment variables are passed to the `pm install` process as an inline shell prefix (`KEY="value" pm install ...`), following the same pattern as the existing `PACKAGES_VERSION` and `REGISTRY` variables. Variable names are validated against the POSIX pattern `[a-zA-Z_][a-zA-Z0-9_]*` at config parse time; invalid names produce a clear configuration error (S015). Empty string values are allowed (POSIX semantics).

The unified `InstallCmd` signature was extended to accept an optional `env map[string]string` parameter:

```go
InstallCmd func(workdir, specFile string, specList []string, env map[string]string) string
```

When `env` is nil or empty, behavior is unchanged (backward compatible). The build output logs the full key=value pairs for transparency, and users are responsible for not placing secrets directly in env var values (S015).

See also: [Package ecosystem registry](./package-ecosystem-registry.md), [PM SBOM collection](./pm-sbom-collection.md), [Build secrets](./build-secrets.md).