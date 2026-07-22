# Research: Not Enforce pm Determinism

**Phase**: Phase 0 — Research & Outline
**Date**: 2026-07-22
**Spec**: `specs/009-not-enforce-pm-determinism/spec.md`

## Overview
**Overview**

This feature builds on the `006-enforce-pm-determinism` revert but improves the implementation by unifying `os-pm` into the `PackageEcosystem` registry (extended to support inline package lists) and using `pm info --installed --json` for SBOM state capture.

## Key Decisions

### Decision 1: Unified `PackageEcosystem` with simplified `InstallCmd` signature

**Decision**: Simplify the `PackageEcosystem` struct by removing separate inline-package-list fields (`SkipWorkdir`, `SkipSpec`, `SkipLock`, `PackagesInstallCmd`) and instead using a single unified `InstallCmd` signature that works for ALL ecosystem types:

```go
InstallCmd func(workdir, specFile string, specList []string) string
```

- File-based ecosystems (go-mod, python-uv, etc.) use `workdir` and `specFile`; `specList` is nil
- Inline-package-list ecosystems (`os-pm`) use `specList`; `workdir` and `specFile` are empty
- Each ecosystem's `InstallCmd` encapsulates ALL logic: environment setup, install command, and SBOM state capture
- `os-pm` is added back to the `ecosystems` registry with its own `InstallCmd`

**Rationale**: The previous approach of having separate `SkipWorkdir`, `SkipSpec`, `SkipLock` flags and `PackagesInstallCmd` field was too complex and created a messy implementation. By expanding the `InstallCmd` signature to accept an optional `specList` parameter, we eliminate the need for separate fields entirely. `GeneratePackagesCommands()` becomes a single uniform call for all ecosystem types — no special-casing.

**Alternatives considered**:
- Keeping `os-pm` as a special case outside the registry — rejected because it creates special-casing in every downstream function and test
- Adding `SkipWorkdir`/`SkipSpec`/`SkipLock`/`PackagesInstallCmd` fields (previous design) — rejected as too messy and complex
- Using a separate `SpecType` enum — rejected because the single `InstallCmd` signature is simpler

### Decision 2: `PackagesSpec` struct for inline package lists

**Decision**: Keep the `PackagesSpec` struct with `Packages []string` on `PackagesDirective`, but `os-pm` is now registered in `ecosystems` with the new inline-package-list fields. The `PackagesDirective` struct retains both `Spec PackagesSpec` and `FileBased FileBasedSpec` fields, but `validate()` and `toDirective()` dispatch based on the ecosystem's flags rather than special-casing `os-pm` by type.

**Rationale**: The `PackagesDirective` struct needs both fields to support both ecosystem types. The dispatch logic is now driven by the ecosystem registry, not by type comparison. This eliminates `if d.Type == PackagesDirectiveTypeOSPM` checks throughout the codebase.

**Alternatives considered**:
- Using a single `Spec` field with an interface type — rejected because it would lose compile-time type safety
- Embedding `PackagesSpec` into `FileBasedSpec` — rejected because it conflates two different concepts

### Decision 3: `workdir` NOT configurable for `os-pm`

**Decision**: The `workdir` field SHALL NOT be accepted for `os-pm` directives. Specifying `workdir` in an `os-pm` directive produces a validation error.

**Rationale**: Before the enforce-pm-determinism feature, `os-pm` did not have a `workdir` field. The `workdir` concept was introduced as part of the file-based ecosystem unification. Since `os-pm` is reverting to the inline model, `workdir` is no longer applicable.

**Alternatives considered**:
- Allowing `workdir` with a default of `/` — rejected per user requirement (FR-006)
- Ignoring `workdir` silently — rejected because silent ignoring of configuration fields is confusing

### Decision 4: SBOM via `pm` index file

**Decision**: SBOM collection for `os-pm` SHALL read `/var/lib/pm/index.json` — a file that `pm` writes itself with the current state of installed packages. The file is read via `ReadFileFromImage` during the SBOM phase. No separate `pm info --installed --json` command is run by werf.

**Rationale**: The `pm` tool already maintains `/var/lib/pm/index.json` as its own state file with information about installed packages. Reading this file directly is simpler and more reliable than running a separate command. We do not need to capture state ourselves — `pm` does it.

**Alternatives considered**:
- Running `pm info --installed --json` and capturing to a file (previous design) — rejected because `pm` already maintains its own index file
- Running `pm info --installed --json` via `RunCommandInImage` during SBOM — rejected because it introduces a runtime dependency on `pm` during SBOM
- Using syft catalogers to scan package manager directories — rejected because `pm`'s filesystem layout is not a stable contract for syft

### Decision 5: Extensible env var constructor

**Decision**: Replace `resolvePmEnvFromSecrets()` with an extensible constructor pattern:
- `envVarTmpl(name, secretMount, catBinPath string) string` — generates a template for a single env var (e.g., `PACKAGES_VERSION="${PACKAGES_VERSION:-$(cat /run/secrets/PACKAGES_VERSION 2>/dev/null || true)}"`)
- `joinEnvPrefix(vars ...string) string` — joins multiple env var templates into a prefix string prepended before the command
- The constructor must be testable: unit tests for individual template generation and full prefix composition
- This design easily extends to additional env vars beyond `PACKAGES_VERSION` and `REGISTRY`

**Alternatives considered**:
- Current hardcoded `resolvePmEnvFromSecrets()` — rejected because it's not extensible for future env vars
- Using a single string with all env vars — rejected because it's less maintainable and testable

### Decision 6: `ContainerFactoryVersionSnapshotCmd()` removal

**Decision**: `ContainerFactoryVersionSnapshotCmd()` SHALL be removed. The version for SBOM purl generation is obtained from `PACKAGES_VERSION` environment variable directly (already set in the env var prefix), or from a `pm` command if needed.

**Rationale**: This function wrote `PACKAGES_VERSION` to a file so it could be read later during SBOM. With the new env var constructor, `PACKAGES_VERSION` is already available as an environment variable in the build context — there's no need to persist it to a file separately.

**Alternatives considered**:
- Keeping the function but reading the value from env var instead — rejected because the function itself becomes unnecessary

## Summary of Code Changes

| File | Change |
|------|--------|
| `pkg/config/packages_directive.go` | Simplify `PackageEcosystem`: unified `InstallCmd func(workdir, specFile string, specList []string) string`; restore `PackagesSpec` struct, `normalizePackages()`, add `os-pm` to `ecosystems` registry; add `PmIndexFile` constant (`/var/lib/pm/index.json`) |
| `pkg/config/raw_packages_directive.go` | Update `fillFileBasedSpec()` to set `FileBased.Spec` and `Spec.Packages` based on ecosystem `InstallCmd` |
| `pkg/config/packages_commands.go` | Simplify to uniform `eco.InstallCmd()` for ALL types; add extensible env var constructor (`envVarTmpl` + `joinEnvPrefix`); implement `os-pm` InstallCmd (no capture); remove `ContainerFactoryVersionSnapshotCmd()` |
| `pkg/config/stapel_image_base.go` | Remove `OSPMLockPath()`, keep `HasOSPMPackages()` |
| `pkg/build/build_phase.go` | `osPmLockPath` → `hasOsPmPackages` bool |
| `pkg/build/sbom_step.go` | `osPmLockPath` → `osPmEnabled` bool, `CollectBOM(ctx, backend, imageRef)` without `lockPath` |
| `pkg/sbom/packages/os_pm/os_pm.go` | Rename `ParsePmLockJSON` → `ParsePmInstalledJSON`, remove `pmLockFile` struct |
| `collect.go` | `collectPacketsFromLock` → `collectInstalledPackets`, read `/var/lib/pm/index.json` via `ReadFileFromImage` |
| `pkg/sbom/packages/os_pm/os_pm_test.go` | Update test references |
| `pkg/sbom/packages/os_pm/testdata/pm_info_installed.json` | Revert to flat format |
| `pkg/sbom/managedinput/managedinput_test.go` | Update `os-pm` entry to use new `PackageEcosystem` fields |
| `test/e2e/sbom/packages_test.go` | Update expectations |
| `test/e2e/sbom/lifecycle_test.go` | Update expectations |
| `test/e2e/sbom/gost_test.go` | Update expectations |
| `test/e2e/sbom/stage_dependencies_test.go` | Update expectations |
| `test/e2e/sbom/_fixtures/inject/` | Remove `pm.yaml`/`pm.lock` fixtures |