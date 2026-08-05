---
title: OS Package Management (os-pm) in werf
type: concept
sources: [S003]
updated: 2026-07-29
---

OS-level packages in werf are declared inline in `werf.yaml` using the `os-pm` type, which installs packages via the `pm` tool during the build phase (S003). For the general file-based package ecosystem registry pattern, see [Package ecosystem registry](./package-ecosystem-registry.md).

## Inline syntax

```yaml
packages:
  - type: os-pm
    spec:
      - curl==8.12.1
      - jq
```

The `spec` field is a list of package name strings, each optionally including a version constraint. The `workdir` field is NOT configurable for `os-pm` — specifying it produces a validation error (S003). An empty `spec` list is also rejected at validation.

## Unified PackageEcosystem registry

The `PackageEcosystem` struct in `pkg/config/` uses a single unified `InstallCmd` signature that works for all ecosystem types:

```go
InstallCmd func(workdir, specFile string, specList []string) string
```

- File-based ecosystems (go-mod, python-uv, etc.) use `workdir` and `specFile`; `specList` is nil.
- Inline-package-list ecosystems (os-pm) use `specList`; `workdir` and `specFile` are empty.
- Each ecosystem's `InstallCmd` encapsulates ALL logic: environment setup, install command, and SBOM state capture (S003).

This eliminates the need for separate `SkipWorkdir`, `SkipSpec`, `SkipLock`, and `PackagesInstallCmd` fields that were present in the previous design. `GeneratePackagesCommands()` now calls `eco.InstallCmd()` uniformly for all types — no special-casing (S003).

## Paradigm difference

The file-based spec+lock model (pm.yaml/pm.lock) was a misfit for OS-level package managers because they do not enforce determinism the way language-specific package managers (go-mod, python-uv, rust-cargo) do. OS-level PMs operate in a fundamentally different paradigm, making inline syntax the appropriate model (S003).

See also: [PM SBOM collection](./pm-sbom-collection.md).