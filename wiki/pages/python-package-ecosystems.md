---
title: Python Package Ecosystems (uv, pip, poetry)
type: concept
sources: [S007]
updated: 2026-07-29
---

Three Python package manager types — `python-uv`, `python-pip`, and `python-poetry` — are registered in the `PackageEcosystem` registry as the first file-based ecosystems. They establish the pattern that subsequent ecosystem types (rust-cargo, javascript-*, lua-rock) follow (S007).

## Configuration

```yaml
packages:
  - type: python-uv
    workdir: /app
```

| Type | Default spec | Default lock | Install command |
|------|-------------|--------------|-----------------|
| `python-uv` | `pyproject.toml` | `uv.lock` | `uv sync --frozen` |
| `python-pip` | `requirements.txt` | (none — rejected) | `pip install --no-cache-dir -r <spec>` |
| `python-poetry` | `pyproject.toml` | `poetry.lock` | `poetry sync` |

## Lock semantics

- **`python-uv`**: `uv sync --frozen` ensures `uv.lock` exists and is in sync — the build fails if the lock file is missing or outdated (S007).
- **`python-poetry`**: `poetry sync` enforces lock file consistency; `poetry.lock` is expected to be present (S007).
- **`python-pip`**: pip has no lock semantics. The `lock` field in YAML is rejected at config validation. Users are expected to pin versions directly in `requirements.txt` (S007).

## SBOM collection

All three types use syft's `python-package-cataloger` for SBOM generation. The cataloger scans the spec file and, where applicable, the lock file. The `buildResolvers()` function in `pkg/sbom/managedinput` derives cataloger entries dynamically from the ecosystem registry (S007).

## Subsequent types

The pattern established by the Python types — a constant, a `PackageEcosystem` map entry, and the `FileBasedSpec` integration — is reused by all later file-based ecosystem additions: `rust-cargo`, `javascript-npm`/`javascript-yarn`/`javascript-pnpm`, and `lua-rock`. Each follows the same declarative approach (S007).

See also: [Package ecosystem registry](./package-ecosystem-registry.md), [Rust Cargo package ecosystem](./rust-cargo-package-ecosystem.md), [JavaScript package ecosystems](./javascript-package-ecosystems.md), [LuaRocks package ecosystem](./lua-rock-package-ecosystem.md).