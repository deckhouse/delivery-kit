---
title: LuaRocks Package Ecosystem (lua-rock)
type: concept
sources: [S004]
updated: 2026-07-29
---

`lua-rock` is a file-based package ecosystem type in werf's `PackageEcosystem` registry, following the same pattern as [Rust Cargo](./rust-cargo-package-ecosystem.md) (`rust-cargo`). It installs Lua dependencies declared in a `.rockspec` file via the `luarocks` tool (S004).

## Configuration

```yaml
packages:
  - type: lua-rock
    workdir: /app
    spec: app-0.1-1.rockspec
```

- **`workdir`** is required — the directory where the rockspec resides.
- **`spec`** is required — there is no default filename because rockspec filenames follow the `<name>-<version>-<revision>.rockspec` convention and cannot be guessed (S004).
- **`lock`** is rejected at validation — LuaRocks does not have a lock file concept (S004).

## Install command

The generated command is:

```
cd "<workdir>" && luarocks install --only-deps "<spec>"
```

The `--only-deps` flag installs only the dependencies declared in the rockspec, not the package itself. This is the correct semantic for the `packages` stage (prepare dependencies for the build stage) (S004).

## SBOM collection

syft's `lua-rock-cataloger` scans the rockspec to produce the SBOM. The cataloger is mapped from the ecosystem registry entry, with the spec source path only (no lock file). SBOM filtering keeps only components found by the declared path (S004).

## Determinism

LuaRocks does not provide a `--frozen` equivalent or a lock file mechanism. Unlike `go-mod` (go.sum checksums), `python-uv` (`--frozen`), or [rust-cargo](./rust-cargo-package-ecosystem.md) (Cargo.lock required by default), `lua-rock` cannot guarantee reproducible dependency resolution at the tool level. This is analogous to `python-pip`. Users who need determinism must pin exact versions in their `.rockspec` file (S004).

## Naming convention

`lua-rock` (not `luarocks`) follows the established `<language>-<manager>` naming pattern used by the Python types (`python-uv`, `python-pip`, `python-poetry`) and Rust (`rust-cargo`), avoiding ambiguity (S004).

## Zero infrastructure change

Adding `lua-rock` required only a new constant (`PackagesDirectiveTypeLuaRock`) and a single entry in the `ecosystems` map. The existing `FileBasedSpec` + ecosystem registry pattern handled everything — no new interfaces, structs, or switch cases were needed (S004).

See also: [OS package management](./os-pm-package-management.md).