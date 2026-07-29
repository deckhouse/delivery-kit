---
title: SBOM Collection for OS Packages (os-pm)
type: decision
sources: [S003]
updated: 2026-07-29
---

## Chosen approach

SBOM state for `os-pm` is read from `/var/lib/pm/index.json` — a file that `pm` itself maintains with the current state of installed packages. The file is read via `ReadFileFromImage` during the SBOM phase. No separate capture command is run by werf (S003).

## Why

- The `pm` tool already maintains its own index file with installed packages information — reading it directly is simpler and more reliable than running a separate command.
- No need for werf to capture state itself — `pm` does it.

## Alternatives rejected

- **Running `pm info --installed --json` and capturing to a file (previous design)**: rejected because `pm` already maintains its own index file.
- **Running `pm info --installed --json` via `RunCommandInImage` during SBOM**: rejected — introduces a runtime dependency on `pm` during SBOM collection.
- **Using syft catalogers to scan package manager directories**: rejected because `pm`'s filesystem layout is not a stable contract for syft (S003).

## Env var constructor

The install command is composed with required environment variables set inline. The extensible constructor pattern uses:

- `envVarTmpl(name string) string` — generates a template for a single env var (e.g., `PACKAGES_VERSION="${PACKAGES_VERSION:-$(cat /run/secrets/PACKAGES_VERSION 2>/dev/null || true)}"`).
- `joinEnvPrefix(vars ...string) string` — joins multiple env var templates into a prefix string prepended before the command.

The composite command for `os-pm` produces: (1) create `/var/lib/pm/` directory, (2) resolve `PACKAGES_VERSION` and write it to `/var/lib/pm/container-factory-version`, (3) run `PACKAGES_VERSION=<...> REGISTRY=<...> pm install <pkg_1> <pkg_2> ...` (S003).

This replaces the removed `ContainerFactoryVersionSnapshotCmd()` — the version file is now written as part of the `os-pm` InstallCmd itself.

See also: [OS package management](./os-pm-package-management.md).