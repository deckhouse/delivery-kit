# Research: lang-pkg-env-vars

**Branch**: `013-lang-pkg-env-vars` | **Date**: 2026-08-03 | **Plan**: [plan.md](plan.md)

## Overview

Investigated the codebase to understand how environment variable support for OS package managers (`os-pm`) was implemented and how to reuse the same mechanism for language package managers. All findings are grounded in the codebase at `pkg/config/`.

---

## 1. How `os-pm` Env Vars Work

### Decision
Environment variables are passed to OS package manager subprocesses via **inline shell prefix**. The `formatEnvVars()` function in `packages_commands.go` converts a `map[string]string` to a sorted, space-separated inline prefix string.

### Rationale
- Inline prefix (`KEY1="val1" KEY2="val2" pm install curl`) is the simplest POSIX-compatible mechanism — no new binary wrappers, no config files, no process environment mutation.
- The shell automatically scopes these variables to the single command invocation, avoiding cross-contamination between package managers.
- Already proven in the `os-pm` feature (012-os-pm-env-vars).

### Mechanism
1. **Config parsing** (`raw_packages_directive.go`): `env` is parsed from YAML into `rawPackagesDirective.Env map[string]string` and POSIX-validated via `posixEnvNameRe` regex.
2. **Command generation** (`packages_commands.go`): `GeneratePackagesCommands()` iterates `[]*PackagesDirective`, calls `eco.InstallCmd(workdir, specFile, specList, pkg.Env)` for each.
3. **Formatting** (`packages_commands.go:formatEnvVars()`): Sorts keys alphabetically with `samber/lo.Keys` + `sort.Strings`, produces `KEY="val"` pairs. Empty input returns `""`.
4. **Execution** (`build/builder/shell.go`): Commands stored in `Shell.Packages []string` are written to container scripts and executed during the `packages` build stage.

### Alternatives Considered
- **OS-level env injection** (e.g., `/etc/environment` or `systemd --setenv`): Overkill for per-package-manager scoping, global pollution risk.
- **Wrapper script**: Adds indirection, harder to debug. Inline prefix is trivially visible in build logs.
- **Child process `os.Environ()` merge**: Requires forking a new binary or rewriting the build executor — inline prefix works at the shell level without Go code changes.

---

## 2. Why Language Package Types Currently Ignore `env`

### Decision
Each language type's `InstallCmd` function signature accepts `env map[string]string` as the 4th parameter but binds it to `_`. The `GeneratePackagesCommands()` caller already passes `pkg.Env` — the data flows to the right place but is discarded.

### Rationale
The `os-pm` feature added the `env` parameter to the `PackageEcosystem.InstallCmd` type signature so that all ecosystems share the same interface. Language types were left as `_ map[string]string` because the feature scope was `os-pm` only.

### Evidence (from `packages_directive.go`):

```go
// All 9 language types currently do this:
InstallCmd: func(workdir, _ string, _ []string, _ map[string]string) string {
    return fmt.Sprintf("cd %q && go mod download", workdir)
},
```

### What Must Change
Replace `_ map[string]string` with `env map[string]string` and prepend `formatEnvVars(env)` when non-empty. The `formatEnvVars` function is already package-private in `pkg/config` and accessible from `packages_directive.go` (same package).

---

## 3. Existing Test Patterns

### Decision
Extend `packages_commands_test.go` with new table entries for each language type, following the same `DescribeTable` pattern used for `os-pm` env var tests.

### Rationale
- Tests are co-located (`packages_commands_test.go` in `pkg/config`).
- The existing `nonOsPmEntry` table ("ignores env for non-os-pm package types") must be updated: it tests current behavior (env ignored) and will need new entries or migration to reflect the new behavior (env wired).
- Individual type-specific config parsing tests exist in `packages_directive_go_mod_test.go`, `packages_directive_python_test.go`, `packages_directive_javascript_test.go`, `packages_directive_rust_test.go`, `packages_directive_lua_test.go` — these may need `env` test entries for `rawPackagesDirective` parsing.

### Test Scenarios to Cover
1. New env vars appear as inline prefix before the install command (1 test per language type + 1 table for edge cases).
2. Backward compatibility: `env` nil or empty → command unchanged (1 test per type or shared table).
3. Env var name validation is already tested in `raw_packages_directive_test.go` — no change needed.

---

## 4. Implementation Scope

### Files to Modify
| File | Change | Risk |
|------|--------|------|
| `pkg/config/packages_directive.go` | Wire `env` into all 9 language `InstallCmd` funcs | Low — mechanical change, same pattern repeated |
| `pkg/config/packages_commands_test.go` | Update "ignores env" tests to "passes env"; add positive tests for each language type | Low — following existing pattern |
| `pkg/config/packages_directive_*_test.go` (optional) | Add `env` entries to type-specific config parsing tests | Low — extension of existing `DescribeTable` entries |

### Files NOT to Modify
| File | Reason |
|------|--------|
| `pkg/config/raw_stapel_image.go` | Already calls `GeneratePackagesCommands()` when SBOM enabled — no change needed |
| `pkg/config/raw_packages_directive.go` | Already parses and validates `env` for all types — no change needed |
| `pkg/config/packages_commands.go` | `GeneratePackagesCommands()` already passes `pkg.Env` to `InstallCmd` — no change needed |
| `pkg/build/builder/shell.go` | Already reads `Shell.Packages` — change is transparent to the builder |
| `pkg/build/stage/packages.go` | Already calls `builder.Packages()` — change is transparent |

---

## 5. Key Risks and Mitigations

| Risk | Likelihood | Mitigation |
|------|-----------|------------|
| Escaping issues with special characters in env var values | Low | `formatEnvVars` uses `%q` (Go quoting) which produces shell-safe double-quoted strings |
| SBOM-gated execution means packages feature requires SBOM | Medium | Existing behavior from `os-pm` — not a new risk. Documented in spec as known constraint |
| A language package manager may not support certain env vars | Low | Env vars are silently ignored by the package manager if unsupported — per spec Edge Cases |
| Backward compatibility regression for missing/long-running env-less configs | Low | Empty/nil `env` produces empty prefix, yielding identical command string |