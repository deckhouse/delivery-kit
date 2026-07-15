---
status: migrated
feature: rust-cargo
created: 2026-07-15
source: branch feat/sbom/get-rust-sbom
---

# Implementation Plan: Rust Cargo Package Ecosystem

## Technical Context

This feature adds Rust/Cargo support to werf's `packages` config directive and its SBOM integration. It follows the exact same pattern as the Python ecosystems, adding a single entry to the existing `PackageEcosystem` registry.

### Frameworks and Libraries

- **Go standard library** (`fmt`) — used for command generation
- **gopkg.in/yaml.v2** — YAML unmarshaling of raw config directives (existing)
- **syft** (via `pkg/sbom/scanner`) — SBOM component cataloging using `rust-cargo-lock-cataloger`
- **ginkgo/gomega** (test) — BDD-style tests for config parsing and SBOM filtering
- **CycloneDX** (via `github.com/CycloneDX/cyclonedx-go`) — BOM data structures

### Ecosystem Registry Addition

A single entry added to the existing `ecosystems` map:

| Field | Value |
|-------|-------|
| `Type` | `PackagesDirectiveTypeRustCargo` |
| `DefaultSpec` | `Cargo.toml` |
| `DefaultLock` | `Cargo.lock` |
| `InstallCmd` | `cd "<workdir>" && cargo fetch` |
| `CatalogerName` | `rust-cargo-lock-cataloger` |

### Architecture Changes

1. **New constant** — `PackagesDirectiveTypeRustCargo` added to the existing type constants in `packages_directive.go`
2. **New ecosystem entry** — Single `PackageEcosystem` struct entry in the `ecosystems` map
3. **Zero refactoring needed** — The existing `FileBasedSpec`, `fillFileBasedSpec`, `GeneratePackagesCommands`, and `buildResolvers` all work generically through the registry; no code changes beyond adding the entry

## Project Structure

```
pkg/config/
  packages_directive.go              — New constant + ecosystem entry (8 lines added)
  packages_directive_rust_test.go    — New: unmarshal, defaults, error cases (104 lines)

pkg/sbom/managedinput/
  managedinput_test.go               — Extended: ToCatalogers and FilterBOMBySourcePaths tests (135 lines added)

pkg/build/stage/
  packages_test.go                   — Extended: GeneratePackagesCommands tests (25 lines added)

test/e2e/sbom/
  cargo_test.go                      — New: e2e test (42 lines)
  _fixtures/inject/cargo_simple/     — New: fixture (Cargo.toml, Cargo.lock, etc.)

docs/_data/
  werf_yaml.yml                      — Updated type descriptions
docs/pages_en/usage/build/stapel/instructions.md  — Updated docs (added rust-cargo section)
docs/pages_ru/usage/build/stapel/instructions.md  — Updated docs (added rust-cargo section)
```

## Complexity Assessment

- **File count**: ~14 files changed (1 source, 3 unit test, 1 e2e + fixture, 3 docs)
- **Source LOC added**: ~8 (net) — one constant + one ecosystem entry
- **Test LOC added**: ~260 (unit) + ~42 (e2e) + fixture data
- **Dependency changes**: None — all new types use existing packages and tools
- **Risk**: Very low — the feature is purely additive; no existing behavior is modified; the registry pattern already exists and is proven by Go-mod and Python types

## Design Decisions

1. **Zero infrastructure change** — The `FileBasedSpec` + ecosystem registry pattern already handles everything needed. Adding `rust-cargo` requires only a constant and a map entry. No new interfaces, no new structs, no new switch cases.
2. **`cargo fetch` over `cargo build`** — `cargo fetch` fetches dependencies to the local registry cache without compiling, which is the correct semantic for the `packages` stage (prepare dependencies). Actual compilation happens in the user's `install` or `build` stage.
3. **No `--frozen` flag** — Unlike `uv sync --frozen`, `cargo fetch` inherently works with `Cargo.lock`; if the lock file is missing or outdated, Cargo will error by default.
4. **Naming convention** — `rust-cargo` (not just `cargo`) follows the established `<language>-<manager>` naming pattern from the Python types (`python-uv`, `python-pip`, `python-poetry`), avoiding ambiguity.