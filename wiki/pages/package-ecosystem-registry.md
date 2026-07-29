---
title: PackageEcosystem Registry and FileBasedSpec
type: concept
sources: [S007]
updated: 2026-07-29
---

The `PackageEcosystem` registry is the central pattern for registering file-based package manager types in werf. It was introduced to replace hardcoded switch statements with a declarative map-based approach (S007).

## Registry structure

A central `ecosystems` map (`map[PackagesDirectiveType]PackageEcosystem`) registers all file-based package types. Each entry holds:

- **`Type`** — Canonical type constant (e.g., `PackagesDirectiveTypePythonUv`).
- **`DefaultSpec`** — Default manifest file name (e.g., `pyproject.toml`).
- **`DefaultLock`** — Default lock file name, empty if not applicable.
- **`InstallCmd`** — Function returning the package manager install command.
- **`CatalogerName`** — syft cataloger for SBOM generation.

## FileBasedSpec

All file-based package ecosystems share a single `FileBasedSpec` struct with `Workdir`, `Spec`, and `Lock` fields. This replaced the previous `GoModSpec` that was specific to Go modules. The `fillFileBasedSpec()` function reads defaults from the ecosystem registry, validates lock availability, and returns an error on invalid spec type (S007).

## Design decisions

- **Ecosystem registry over switch**: A map-based registry makes adding new package types purely declarative — add a constant and an entry. The old switch on `PackagesDirectiveType` is replaced entirely for file-based types (S007).
- **Separate OSPM handling**: OS package manager (`os-pm`) remains distinct because its spec structure (`PackagesSpec.Packages` list) is incompatible with the file-based model (S007).
- **Deterministic resolver ordering**: `buildResolvers()` in `pkg/sbom/managedinput` sorts types alphabetically so that SBOM cataloger order is stable across invocations and builds (S007).
- **Quoted `workdir` in shell commands**: All generated `cd` commands use `%q` formatting (`cd "/app" && ...`) to handle paths with spaces or special characters (S007).

## Downstream consumption

- `GeneratePackagesCommands` dispatches commands via the ecosystem registry.
- `buildResolvers` dynamically constructs `inputResolver` entries from `config.Ecosystems()`.
- `ToCatalogers` maps ecosystem types to syft catalogers via the registry.

See also: [Python package ecosystems](./python-package-ecosystems.md), [OS package management](./os-pm-package-management.md), [JavaScript package ecosystems](./javascript-package-ecosystems.md), [Rust Cargo package ecosystem](./rust-cargo-package-ecosystem.md), [LuaRocks package ecosystem](./lua-rock-package-ecosystem.md).