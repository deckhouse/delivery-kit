---
title: JavaScript Package Ecosystems (npm, yarn, pnpm)
type: concept
sources: [S005]
updated: 2026-07-29
---

Three JavaScript package manager types — `javascript-npm`, `javascript-yarn`, and `javascript-pnpm` — are registered in werf's `PackageEcosystem` registry as file-based ecosystems, following the same pattern as the [Python](./python-package-ecosystems.md) and [Rust](./rust-cargo-package-ecosystem.md) types (S005).

## Configuration

```yaml
packages:
  - type: javascript-npm
    workdir: /app
```

All three types default to `package.json` as the spec file and each has its own default lock file:

| Type | Default spec | Default lock | Install command |
|------|-------------|--------------|-----------------|
| `javascript-npm` | `package.json` | `package-lock.json` | `npm ci` |
| `javascript-yarn` | `package.json` | `yarn.lock` | `yarn install --frozen-lockfile` |
| `javascript-pnpm` | `package.json` | `pnpm-lock.yaml` | `pnpm install --frozen-lockfile` |

## Install command decisions

- **`npm ci`** is used instead of `npm install` because it is faster, fails if `package-lock.json` is missing or out of sync, and produces deterministic installs — the correct choice for CI/CD (S005).
- **`--frozen-lockfile`** for yarn and pnpm ensures lock file consistency and fails the build if the lock file is out of date (S005).

## Shared cataloger setup

All three types use Syft's `javascript-lock-cataloger` for lock file scanning and `javascript-package-cataloger` for `package.json` direct dependency metadata. The `buildResolvers()` function generates one resolver entry per type, each with the same cataloger name (`javascript-lock-cataloger`) but different lock file source paths. This is handled transparently because `inputResolver` does not require unique cataloger names (S005).

## Naming convention

`javascript-<manager>` (not `js-<manager>` or `<manager>-js`) follows the `<language>-<manager>` pattern established by [python-uv](./python-package-ecosystems.md), [python-pip](./python-package-ecosystems.md), [python-poetry](./python-package-ecosystems.md), and [rust-cargo](./rust-cargo-package-ecosystem.md) (S005).

## Three separate types

Each JavaScript package manager gets its own type rather than a single `javascript` type with a manager sub-field. This keeps the YAML flat and unambiguous, and avoids ecosystem-specific validation logic — following the same approach as Python (`python-uv`, `python-pip`, `python-poetry`) (S005).

See also: [LuaRocks package ecosystem](./lua-rock-package-ecosystem.md), [OS package management](./os-pm-package-management.md).