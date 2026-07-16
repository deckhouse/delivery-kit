---
status: migrated
feature: lua-rock
created: 2026-07-16
source: branch feat/sbom/get-lua-sbom
---

# Lua Rock Package Ecosystem for werf Packages Directive

## User Scenarios

### Scenario: Declare lua-rock-managed Lua dependencies

A user has a Lua project with a `.rockspec` file that declares dependencies. They add a `packages` directive in `werf.yaml`:

```yaml
packages:
  - type: lua-rock
    workdir: /app
    spec: app-0.1-1.rockspec
```

- **WHEN** the build runs
- **THEN** werf runs `cd "/app" && luarocks install --only-deps "app-0.1-1.rockspec"` inside the build container, fetching and installing the dependencies declared in the rockspec
- **AND** syft's `lua-rock-cataloger` scans the `.rockspec` to produce the SBOM
- **AND** SBOM filtering keeps only components found by that declared path

### Scenario: Mix Lua Rock with other package types

A project uses both Go modules and Lua dependencies:

```yaml
packages:
  - type: go-mod
    workdir: /app
  - type: lua-rock
    workdir: /app/scripts
    spec: lib-2.0-1.rockspec
  - type: os-pm
    packages:
      - libssl-dev
```

- **WHEN** the build runs
- **THEN** all three directives produce commands: `go mod download`, `luarocks install --only-deps "lib-2.0-1.rockspec"`, `pm install libssl-dev`
- **AND** each directive contributes its own cataloger for SBOM scanning
- **AND** the `lua-rock-cataloger` only scans the rockspec path (no lock file)

### Scenario: Build fails when rockspec is missing from build context

A user declares `lua-rock` with a rockspec that does not exist in the build context:

- **WHEN** the build runs
- **THEN** `luarocks install --only-deps` fails because the `.rockspec` file cannot be found
- **AND** the error message mentions "rockspec" or "luarocks"

## Requirements

### R1: Lua Rock ecosystem type

The `packages` directive SHALL support type `lua-rock` with its own package manager command (`luarocks install --only-deps <spec>`), no default spec filename (required), no lock file (rejected), and cataloger (`lua-rock-cataloger`).

### R2: Ecosystem registry integration

The `lua-rock` type SHALL be registered in the existing `ecosystems` map keyed by `PackagesDirectiveType`. The type sits alongside `go-mod`, `python-*`, and `rust-cargo` — no new infrastructure is needed.

### R3: Command generation via registry

`GeneratePackagesCommands` SHALL dispatch `lua-rock` commands via the ecosystem registry, producing `cd "<workdir>" && luarocks install --only-deps "<spec>"` for each entry.

### R4: SBOM cataloger from ecosystem registry

`ToCatalogers` and `buildResolvers` in `pkg/sbom/managedinput` SHALL derive cataloger entries for `lua-rock` from `config.Ecosystems()`, mapping to `lua-rock-cataloger` with the spec source path only (no lock).

### R5: Spec required (no default)

Unlike other file-based types, `lua-rock` SHALL NOT have a default spec filename. The `spec` field in YAML SHALL be required and must point to a `.rockspec` file. An empty or missing `spec` SHALL be rejected at config validation.

### R6: Lock not supported

The `lock` field in YAML SHALL be rejected at config validation for `lua-rock`. LuaRocks has no lock file concept.

## Success Criteria

- SC1: A `packages` entry with `type: lua-rock`, `workdir: /app`, and `spec: app-0.1-1.rockspec` successfully installs dependencies and generates an SBOM containing `werf-sbom-lua-app@0.1-1` when the rockspec declares that package name and version.
- SC2: An unknown package type (e.g., `luarocks` without the `lua-rock` naming) is rejected at config validation.
- SC3: A `lua-rock` entry without `workdir` is rejected at config validation.
- SC4: A `lua-rock` entry without `spec` is rejected at config validation (no fallback default).
- SC5: A `lua-rock` entry with a `lock` field is rejected at config validation.

## Non-Requirements

### N1: Determinism enforcement

Unlike `go-mod` (go.sum checksums), `python-uv` (`--frozen` flag), or `rust-cargo` (Cargo.lock required by default), `lua-rock` does **not** have a lock file or a `--frozen` equivalent. LuaRocks does not provide such a mechanism. Users who require deterministic dependency resolution must pin exact versions in their `.rockspec` file. This is analogous to `python-pip`, which also lacks lock semantics.

## Assumptions

- LuaRocks (`luarocks`) must be pre-installed in the builder image; werf does not install it.
- The `.rockspec` file is expected to be present in the build context; `luarocks install --only-deps` will fail if the file is missing.
- The `--only-deps` flag ensures that only dependencies are resolved and installed, not the package declared by the rockspec itself — this is compatible with the `packages` stage semantics of preparing dependencies for the build.
- LuaRocks resolves dependencies based on version constraints in the rockspec. Without a lock file, the same rockspec may resolve different dependency versions over time.
