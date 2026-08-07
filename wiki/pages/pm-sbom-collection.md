---
title: SBOM Collection for OS Packages (os-pm)
type: decision
sources: [S003, S018]
updated: 2026-08-07
---

## Chosen approach

SBOM state for `os-pm` is read from **`pm.lock`** in the build context (host filesystem, under Git) instead of from inside the built container. The existing parser functions (`ParsePmInstalledJSON`, `collectPacketsFromLock`) are reused — `pm.lock` has the same format as the old `/var/lib/pm/index.json` (S018).

## Changed approach (since S003)

When the `os-pm` type migrated from inline syntax (S003) to file-based syntax (S018), the SBOM collection changed:

- Package metadata (names, versions, licenses, dependencies) is now extracted exclusively from `pm.lock` in the build context — no package data is read from inside the built image.
- The file `/var/lib/pm/index.json` SHALL NOT be read from inside the container — `pm.lock` replaces it entirely.
- Only the `ContainerFactoryVersionFile` (`/var/lib/pm/container-factory-version`) is still read from inside the built image via `ReadFileFromImage`, if present. It is used for the `containerfactoryversion` PURL qualifier (S018).

## PM BOMPatcher (PURL enrichment)

After Syft scans `pm.lock` from the build context, the resulting SBOM components lack the `containerFactoryVersion` PURL qualifier (this version only exists inside the built image). A `PMBOMPatcher` (in `pkg/sbom/packages/os_pm/pm_bom_patcher.go`) post-processes the merged BOM to append `containerFactoryVersion=<version>` to each PM component's PURL. It is created in `pkg/build/sbom_step.go` and invoked by `ConvergeWithMerge()`, and matches PM components via `syft:package:foundBy = "os-pm-lock-cataloger"` (S018).

The PM BOMPatcher is applied BEFORE the external refs BOMPatcher in the patchers list so that os-pm components are present in the BOM before PURL resolution (S018).

## Why

- `pm.lock` lives under Git, so SBOM metadata is available without running or inspecting the built container.
- The lock file is deterministic (pinned versions with integrity hashes), matching the pattern used by all other file-based package types (S018).

## Alternatives rejected

- **Reading `/var/lib/pm/index.json` from inside container**: rejected — duplicates the data already available in `pm.lock` in the build context (S018).
- **Running `pm info --installed --json` and capturing to a file (previous design)**: rejected because `pm` already maintains its own lock file.
- **Using syft catalogers to scan package manager directories**: rejected because `pm`'s filesystem layout is not a stable contract for syft (S003).

## Env var constructor

The install command is composed with required environment variables set inline. The extensible constructor pattern uses:

- `formatSecretVar(name string)` — generates a template for a single env var (e.g., `PACKAGES_VERSION="${PACKAGES_VERSION:-$(cat /run/secrets/PACKAGES_VERSION 2>/dev/null || true)}"`).
- `formatEnvVars(env)` — formats user-defined env vars.
- `formatMkdirCommand` — creates the runtime directory `/var/lib/pm/`.
- `formatVersionFileCommand` — writes the container factory version file.

The composite command for `os-pm` produces: (1) `mkdir -p /var/lib/pm`, (2) resolve `PACKAGES_VERSION` and write it to `/var/lib/pm/container-factory-version`, (3) run `<env vars> <secret vars> pm sync --from <lockfile>` (S018).

See also: [OS package management](./os-pm-package-management.md).