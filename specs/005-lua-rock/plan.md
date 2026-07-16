---
status: migrated
feature: lua-rock
created: 2026-07-16
source: branch feat/sbom/get-lua-sbom
---

# Implementation Plan: Lua Rock Package Ecosystem

## Technical Context

This feature adds Lua/LuaRocks support to werf's `packages` config directive and its SBOM integration. It follows the exact same pattern as the Rust Cargo ecosystem, adding a single entry to the existing `PackageEcosystem` registry. The key difference is that `lua-rock` has no default spec and no lock file.

### Frameworks and Libraries

- **Go standard library** (`fmt`) — used for command generation
- **gopkg.in/yaml.v2** — YAML unmarshaling of raw config directives (existing)
- **syft** (via `pkg/sbom/scanner`) — SBOM component cataloging using `lua-rock-cataloger`
- **ginkgo/gomega** (test) — BDD-style tests for config parsing and SBOM filtering
- **CycloneDX** (via `github.com/CycloneDX/cyclonedx-go`) — BOM data structures

### Ecosystem Registry Addition

A single entry added to the existing `ecosystems` map:

| Field | Value |
|-------|-------|
| `Type` | `PackagesDirectiveTypeLuaRock` |
| `DefaultSpec` | `""` (empty — no default, `spec` always required) |
| `DefaultLock` | `""` (empty — no lock file) |
| `InstallCmd` | `cd "<workdir>" && luarocks install --only-deps "<spec>"` |
| `CatalogerName` | `lua-rock-cataloger` |

### Architecture Changes

1. **New constant** — `PackagesDirectiveTypeLuaRock` added to the existing type constants in `packages_directive.go`
2. **New ecosystem entry** — Single `PackageEcosystem` struct entry in the `ecosystems` map with empty `DefaultSpec` and `DefaultLock`
3. **Zero refactoring needed** — The existing `FileBasedSpec`, `fillFileBasedSpec`, `GeneratePackagesCommands`, and `buildResolvers` all work generically through the registry; no code changes beyond adding the entry
4. **Validation behavior** — Because `DefaultSpec` is empty, `fillFileBasedSpec` requires the user to provide `spec` explicitly. If `spec` is missing, the directive has an empty `FileBasedSpec.Spec` and `validate()` rejects it. Similarly, because `DefaultLock` is empty, the `lock` field is rejected by `fillFileBasedSpec`.

## Project Structure

```
pkg/config/
  packages_directive.go              — New constant + ecosystem entry (8 lines added)
  packages_directive_lua_test.go     — New: unmarshal, defaults, error cases (119 lines)

pkg/sbom/managedinput/
  managedinput_test.go               — Extended: ToCatalogers and FilterBOMBySourcePaths tests for lua-rock (~50 lines added)

pkg/build/stage/
  packages_test.go                   — Extended: GeneratePackagesCommands tests (~45 lines added)

test/e2e/sbom/
  lua_test.go                        — New: e2e test (70 lines)
  _fixtures/inject/lua_simple/       — New: fixture (werf.yaml, app.lua, rockspec, Dockerfile.builder-base, werf-giterminism.yaml)
  _fixtures/negative/lua_missing_rockspec/  — New: negative fixture (missing rockspec scenario)

docs/_data/
  werf_yaml.yml                      — Updated type descriptions
docs/pages_en/usage/build/stapel/instructions.md  — Updated docs (added lua-rock section)
```

## Complexity Assessment

- **File count**: ~14 files changed (1 source, 3 unit test, 1 e2e + 2 fixtures, 2 docs)
- **Source LOC added**: ~8 (net) — one constant + one ecosystem entry
- **Test LOC added**: ~190 (unit) + ~70 (e2e) + ~35 fixture data
- **Dependency changes**: None — all new types use existing packages and tools
- **Risk**: Very low — the feature is purely additive; no existing behavior is modified; the registry pattern already exists and is proven by Go-mod, Python, and Rust types

## Design Decisions

1. **Zero infrastructure change** — The `FileBasedSpec` + ecosystem registry pattern already handles everything needed. Adding `lua-rock` requires only a constant and a map entry. No new interfaces, no new structs, no new switch cases.

2. **`luarocks install --only-deps` over `luarocks install`** — The `--only-deps` flag installs only the dependencies declared in the rockspec, not the package itself. This is the correct semantic for the `packages` stage (prepare dependencies for the build stage).

3. **No default spec, no lock file** — Unlike all other file-based ecosystems, `lua-rock` has no sensible default for `spec` (rockspec filenames follow `<name>-<version>-<revision>.rockspec` convention and cannot be guessed) and no lock file (LuaRocks doesn't have one). This makes `lua-rock` unique in requiring an explicit `spec` and rejecting the `lock` field.

4. **No determinism enforcement** — LuaRocks does not provide a `--frozen` equivalent or a lock file mechanism. Unlike `go-mod` (go.sum checksums), `python-uv` (`--frozen`), or `rust-cargo` (Cargo.lock required by default), `lua-rock` cannot guarantee reproducible dependency resolution at the tool level. This is analogous to `python-pip`. Users who need determinism must pin exact versions in their `.rockspec` file.

5. **Naming convention** — `lua-rock` (not `luarocks`) follows the established `<language>-<manager>` naming pattern from the Python types (`python-uv`, `python-pip`, `python-poetry`) and Rust (`rust-cargo`), avoiding ambiguity.
