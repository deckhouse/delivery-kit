---
title: Rust Cargo Package Ecosystem (rust-cargo)
type: concept
sources: [S006]
updated: 2026-07-29
---

`rust-cargo` is a file-based package ecosystem type in werf's `PackageEcosystem` registry, following the same pattern as the [Python ecosystems](./python-package-ecosystems.md) (`python-uv`, `python-pip`, `python-poetry`). It fetches Rust dependencies declared in `Cargo.toml` and `Cargo.lock` via the `cargo` tool (S006).

## Configuration

```yaml
packages:
  - type: rust-cargo
    workdir: /app
```

- **`workdir`** is required — the directory where `Cargo.toml` and `Cargo.lock` reside.
- **`spec`** defaults to `Cargo.toml`.
- **`lock`** defaults to `Cargo.lock`.

## Install command

The generated command is:

```
cd "<workdir>" && cargo fetch
```

`cargo fetch` fetches dependencies to the local registry cache without compiling — the correct semantic for the `packages` stage (prepare dependencies for the build). Actual compilation happens in the user's `install` or `build` stage (S006).

## Lock validation

Unlike `python-uv` which requires an explicit `--frozen` flag, `cargo fetch` inherently works with `Cargo.lock`. If the lock file is missing or outdated, Cargo will error by default. No `--frozen` flag is needed (S006).

## SBOM collection

syft's `rust-cargo-lock-cataloger` scans `Cargo.toml` and `Cargo.lock` to produce the SBOM. The cataloger is mapped from the ecosystem registry entry with both spec and lock source paths (S006).

## Naming convention

`rust-cargo` (not just `cargo`) follows the established `<language>-<manager>` naming pattern used by the Python types (`python-uv`, `python-pip`, `python-poetry`), avoiding ambiguity (S006).

## Zero infrastructure change

Adding `rust-cargo` required only a new constant (`PackagesDirectiveTypeRustCargo`) and a single entry in the `ecosystems` map. The existing `FileBasedSpec` + ecosystem registry pattern handled everything — no new interfaces, structs, or switch cases were needed (S006).

See also: [LuaRocks package ecosystem](./lua-rock-package-ecosystem.md), [JavaScript package ecosystems](./javascript-package-ecosystems.md), [OS package management](./os-pm-package-management.md).