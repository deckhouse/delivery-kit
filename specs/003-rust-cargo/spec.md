---
status: migrated
feature: rust-cargo
created: 2026-07-15
source: branch feat/sbom/get-rust-sbom
---

# Rust Cargo Package Ecosystem for werf Packages Directive

## User Scenarios

### Scenario: Declare rust-cargo-managed Rust dependencies

A user has a Rust project managed by **Cargo** with a `Cargo.toml` and `Cargo.lock`. They add a `packages` directive in `werf.yaml`:

```yaml
packages:
  - type: rust-cargo
    workdir: /app
```

- **WHEN** the build runs
- **THEN** werf runs `cd "/app" && cargo fetch` inside the build container, fetching locked dependencies
- **AND** syft's `rust-cargo-lock-cataloger` scans `/app/Cargo.toml` and `/app/Cargo.lock` to produce the SBOM
- **AND** SBOM filtering keeps only components found by those declared paths

### Scenario: Mix Rust Cargo with other package types

A project uses both Go modules and Rust dependencies:

```yaml
packages:
  - type: go-mod
    workdir: /app
  - type: rust-cargo
    workdir: /app/native
  - type: os-pm
    packages:
      - libssl-dev
```

- **WHEN** the build runs
- **THEN** all three directives produce commands that are run inside the build container: `go mod download`, `cargo fetch`, `pm install libssl-dev`
- **AND** each directive contributes its own cataloger for SBOM scanning

### Scenario: Multiple rust-cargo entries in one image

A user has a Rust workspace with multiple crates in different directories:

```yaml
packages:
  - type: rust-cargo
    workdir: /app
  - type: rust-cargo
    workdir: /app/native
```

- **WHEN** the build runs
- **THEN** `cargo fetch` runs in both `/app` and `/app/native`
- **AND** each entry produces a separate `rust-cargo-lock-cataloger` entry with its own source paths

## Requirements

### R1: Rust Cargo ecosystem type

The `packages` directive SHALL support type `rust-cargo` with its own package manager command (`cargo fetch`), default manifest file (`Cargo.toml`), default lock file (`Cargo.lock`), and cataloger (`rust-cargo-lock-cataloger`).

### R2: Ecosystem registry integration

The `rust-cargo` type SHALL be registered in the existing `ecosystems` map keyed by `PackagesDirectiveType`. The type sits alongside `go-mod`, `python-uv`, `python-pip`, and `python-poetry` — no new infrastructure is needed.

### R3: Command generation via registry

`GeneratePackagesCommands` SHALL dispatch `rust-cargo` commands via the ecosystem registry, producing `cd "<workdir>" && cargo fetch` for each entry.

### R4: SBOM cataloger from ecosystem registry

`ToCatalogers` and `buildResolvers` in `pkg/sbom/managedinput` SHALL derive cataloger entries for `rust-cargo` from `config.Ecosystems()`, mapping to `rust-cargo-lock-cataloger` with spec and lock source paths.

### R5: Lock validation

`cargo fetch` SHALL be used (no lock-related flags) — Cargo's lock file is always present and consistent when `Cargo.toml` changes are committed together with `Cargo.lock`.

### R6: Default file names

| Type | Default spec | Default lock |
|------|-------------|--------------|
| `rust-cargo` | `Cargo.toml` | `Cargo.lock` |

### R7: Install command

| Type | Command |
|------|---------|
| `rust-cargo` | `cargo fetch` |

## Success Criteria

- SC1: A `packages` entry with `type: rust-cargo` and `workdir: /app` successfully fetches dependencies and generates an SBOM containing `anyhow@1.0.86` when `Cargo.lock` lists that dependency.
- SC2: An unknown package type (e.g., `cargo` without the `rust-` prefix) is rejected at config validation.
- SC3: A `rust-cargo` entry without `workdir` is rejected at config validation.
- SC4: A mixed configuration (`go-mod` + `rust-cargo` + `os-pm`) generates all expected commands and catalogers correctly.
- SC5: Multiple `rust-cargo` entries with different `workdir` values each produce correct `cargo fetch` commands and separate cataloger entries.

## Assumptions

- Rust toolchain (`cargo`) must be pre-installed in the builder image; werf does not install it.
- `Cargo.lock` is expected to be present in the build context; Cargo enforces this by default.
- `cargo fetch` does not install dependencies (it only fetches them to the local registry cache) — this is compatible with the `packages` stage semantics of preparing dependencies for the build.