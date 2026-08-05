# Data Model: Not Enforce pm Determinism

**Phase**: Phase 1 — Design & Contracts
**Date**: 2026-07-22
**Spec**: `specs/009-not-enforce-pm-determinism/spec.md`

## Overview

This document describes the data model for the revert, showing only the `os-pm`-specific structures. All other package ecosystems (`go-mod`, `python-uv`, etc.) remain unchanged. The key structural change is that `os-pm` uses a separate `PackagesSpec` struct instead of `FileBasedSpec`.

## Entities

### `PackagesSpec`

| Field | Type | Description | Validation |
|-------|------|-------------|------------|
| `Packages` | `[]string` | List of OS package names to install, mapped from YAML `spec` key. Each string may include version constraints (e.g., `curl==8.12.1`). | Must not be empty for valid directive; each name is validated by the PM binary at runtime |

**Purpose**: Holds the inline list of package names for `os-pm` directives. This is the data model for `spec: [curl==8.12.1, jq]` syntax.

**State transitions**: None — the struct is populated during YAML unmarshal and used to generate install commands. No runtime state changes.

---

### `PackagesDirective` (updated)

| Field | Type | Description |
|-------|------|-------------|
| `Type` | `PackagesDirectiveType` | Package ecosystem type (e.g., `"os-pm"`, `"go-mod"`) |
| `Spec` | `PackagesSpec` | Used ONLY when `Type == os-pm`. Contains inline package list. |
| `FileBased` | `FileBasedSpec` | Used for all other (file-based) ecosystem types. Includes `Workdir`, `Spec` (file path), `Lock`. |

**Constraints**:
- For `os-pm` type: `Spec.Packages` must be non-empty; `FileBased` is zero-value (unused)
- For file-based types (go-mod, etc.): `FileBased.Workdir` and `FileBased.Spec` must be non-empty; `Spec` is zero-value (unused)
- These two fields are mutually exclusive in practice, enforced by `toDirective()` and `validate()`

---

### `PackagesDirectiveType` (unchanged, shown for reference)

```
PackagesDirectiveTypeOSPM         PackagesDirectiveType = "os-pm"
PackagesDirectiveTypeGoMod        PackagesDirectiveType = "go-mod"
PackagesDirectiveTypePythonUV     PackagesDirectiveType = "python-uv"
...
```

The constant `PackagesDirectiveTypeOSPM` remains in the type constants list. It is simply no longer present in the `ecosystems` registry.

---

### `PackageEcosystem` (simplified)

| Field | Type | Description |
|-------|------|-------------|
| `Type` | `PackagesDirectiveType` | Package ecosystem type identifier |
| `DefaultSpecFile` | `string` | Default spec file name (e.g., `go.mod`, `package.json`) |
| `DefaultLockFile` | `string` | Default lock file name (e.g., `go.sum`, `package-lock.json`) |
| `CatalogerName` | `string` | Syft cataloger name for SBOM (empty = skip for `os-pm`) |
| `InstallCmd` | `func(workdir, specFile string, specList []string) string` | Single install command function for ALL ecosystem types. File-based types use `workdir`+`specFile`, inline-package-list types (`os-pm`) use `specList`. |

**Notes**:
- File-based ecosystems (go-mod, python-uv, etc.) receive their `workdir` and resolved `specFile` path; `specList` is nil
- Inline-package-list ecosystems (`os-pm`) receive their package list in `specList`; `workdir` and `specFile` are empty
- Each ecosystem's `InstallCmd` function encapsulates ALL logic: environment setup, install command generation, and SBOM state capture
- No separate snapshot/version commands — each `pm install` invocation includes environment variables inline
- `GeneratePackagesCommands()` calls `eco.InstallCmd()` uniformly for all types — no special-casing

The registry `ecosystems` map now contains a `PackagesDirectiveTypeOSPM` entry. This causes:
- `Ecosystems()` → returns all ecosystems including `os-pm`
- `GeneratePackagesCommands()` → dispatches based on ecosystem fields (`PackagesInstallCmd` vs `InstallCmd`)
- `validate()` → checks `SkipWorkdir`/`SkipSpec` flags instead of special-casing `os-pm`
- `managedinput.buildResolvers()` → generates cataloger for `os-pm` if `CatalogerName` is set (empty for `os-pm`)

---

## Validation Rules (for `os-pm`)

| Rule | Condition | Error Message |
|------|-----------|---------------|
| R1 | `spec` field in YAML is nil | `"the 'spec' is required for 'os-pm' packages directive entry!"` |
| R2 | `spec` field in YAML is not a `[]interface{}` | `"unsupported packages spec type %T for type 'os-pm'; spec must be a list of package names"` |
| R3 | `spec` list is empty after conversion | `"packages spec must not be empty for type 'os-pm'"` |
| R4 | `workdir` is specified in YAML for `os-pm` | Rejected by `checkOverflow` / structural validation — `workdir` is a known field that will be read but ignored for `os-pm`, OR explicitly validated to produce an error |
| R5 | `spec` is specified simultaneously as both a list (inline package names) and a string (file path) | Invalid YAML — `spec` can't be both a list and a string simultaneously |

## Comparison: Before vs After

| Aspect | Before (post-006) | After (this feature) |
|--------|-------------------|---------------------|
| `os-pm` in ecosystems | ✅ Present with `DefaultSpec: pm.yaml`, `DefaultLock: pm.lock` | ✅ Present with extended fields: `SkipWorkdir`, `SkipSpec`, `SkipLock`, `PackagesInstallCmd` |
| `PackagesSpec` struct | ❌ Removed | ✅ Restored |
| `normalizePackages()` | ❌ Removed | ✅ Restored |
| `Spec` field type | `string` (file path for all) | `interface{}` — string for file-based, []interface{} for os-pm |
| `fillOSPMSpec()` | ❌ Removed | ✅ Replaced by unified `fillFileBasedSpec()` with ecosystem flag dispatch |
| `workdir` for os-pm | Required | ❌ Not configurable (via `SkipWorkdir` flag) |
| Install command | `pm sync --from <workdir>/pm.lock` | `SHAPSHOTTED_ENV=value pm install <pkg_1> <pkg_2> ...` (single command, all packages as args) |
| SBOM collection | `ReadFileFromImage` → parse `pm.lock` | `ReadFileFromImage` → parse `/var/lib/pm/index.json` (written by `pm` itself) |
| `OSPMLockPath()` | ✅ Present | ❌ Removed |
| `HasOSPMPackages()` | ✅ Present | ✅ Preserved |