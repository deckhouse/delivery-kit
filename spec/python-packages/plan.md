---
status: migrated
feature: python-packages
created: 2026-07-10
source: branch feat-sbom-get-python-sbom
---

# Implementation Plan: Python Package Ecosystems

## Technical Context

This feature adds Python package manager support to werf's `packages` config directive and its SBOM integration. It extends the existing Go-module pattern into a general `FileBasedSpec` model.

### Frameworks and Libraries

- **Go standard library** (`fmt`, `maps`, `sort`, `slices`, `strings`) — used in the ecosystem registry and command generation
- **gopkg.in/yaml.v2** — YAML unmarshaling of raw config directives
- **syft** (via `pkg/sbom/scanner`) — SBOM component cataloging using `python-package-cataloger`
- **ginkgo/gomega** (test) — BDD-style tests for config parsing and SBOM filtering
- **CycloneDX** (via `github.com/CycloneDX/cyclonedx-go`) — BOM data structures

### Ecosystem Registry Design

A central `ecosystems` map (`map[PackagesDirectiveType]PackageEcosystem`) registers all file-based package types. Each entry holds:

| Field | Purpose |
|-------|---------|
| `Type` | Canonical type constant |
| `Aliases` | Short name variants (e.g., `uv` → `python-uv`) |
| `DefaultSpec` | Default manifest file name |
| `DefaultLock` | Default lock file name (empty if not applicable) |
| `InstallCmd` | Function returning the package manager install command |
| `CatalogerName` | syft cataloger for SBOM generation |

The alias index (`aliasToType`) is built at package init time from the ecosystem registry.

### Architecture Changes

1. **`GoModSpec` → `FileBasedSpec`** — Struct renamed and generalized with same fields (`Workdir`, `Spec`, `Lock`)
2. **`fillGoModSpec` → `fillFileBasedSpec`** — Reads defaults from ecosystem registry; validates lock availability; returns error on invalid spec type
3. **`GeneratePackagesCommands`** — Refactored from `switch` to registry-based dispatch: OSPM has a dedicated `if` branch, then the rest fall through to ecosystem lookup
4. **`buildResolvers`** in `managedinput.go` — Dynamically constructs input resolvers from `config.Ecosystems()`, sorted alphabetically for deterministic ordering
5. **`rawPackagesDirective.toDirective`** — Added alias resolution before type canonicalization

## Project Structure

```
pkg/config/
  packages_directive.go          — Ecosystem registry, types, FileBasedSpec
  packages_commands.go           — Command generation
  raw_packages_directive.go      — YAML parsing and validation
  helpers_test.go                — Shared test helper (directivesFromYaml)
  packages_directive_go_mod_test.go  — Go-mod specific tests (refactored)
  packages_directive_python_test.go  — Python-specific tests (new)
  raw_packages_directive_test.go     — Validation and normalization tests (extended)

pkg/sbom/managedinput/
  managedinput.go                — buildResolvers, ToCatalogers, FilterBOMBySourcePaths
  managedinput_test.go           — SBOM tests for python catalogers (extended)

test/e2e/sbom/
  pip_test.go                    — E2E: pip install + SBOM
  poetry_test.go                 — E2E: poetry install + SBOM
  uv_test.go                     — E2E: uv sync + SBOM
  _fixtures/inject/pip_simple/     — Fixture: requirements.txt
  _fixtures/inject/poetry_simple/  — Fixture: poetry project
  _fixtures/inject/uv_simple/      — Fixture: uv project

docs/_data/
  werf_yaml.yml                  — Updated type descriptions for Python types
```

## Complexity Assessment

- **File count**: ~12 files changed (6 source, 5 unit test, 4 e2e)
- **Source LOC added**: ~250 (net) across ecosystem registry, command dispatch, SBOM resolvers
- **Test LOC added**: ~400 (unit) + ~130 (e2e) + fixture data
- **Dependency changes**: None — all new types use existing packages and tools
- **Risk**: Low — the refactoring maintains backward compatibility for existing `go-mod` and `os-pm` usage; the `GoModSpec` → `FileBasedSpec` rename is internal only

## Design Decisions

1. **Ecosystem registry over switch** — A map-based registry makes adding new package types purely declarative (add a constant + entry). The old switch on `PackagesDirectiveType` is replaced entirely for file-based types.
2. **Aliases resolved at parse time** — `rawPackagesDirective.toDirective()` canonicalizes aliases before storing, so downstream code only sees canonical types.
3. **Separate OSPM handling** — OS package manager (`os-pm`) remains distinct because its spec structure (`PackagesSpec.Packages` list) is incompatible with the file-based model.
4. **Deterministic resolver ordering** — `buildResolvers()` sorts types alphabetically so that SBOM cataloger order is stable across invocations and builds.
5. **Quoted `workdir` in shell commands** — All generated `cd` commands now use `%q` formatting (`cd "/app" && ...`) to handle paths with spaces or special characters.