---
status: migrated
feature: os-pm-sbom-scratch-and-secret-resolution
created: 2026-07-17
updated: 2026-07-20
source: branch fix/pm-snapshot-stapel-tool-paths
---

# SBOM Scratch Compatibility and Build Secret Resolution for os-pm

**Revision**: 2 — rethinking after the initial stapel-coreutils approach failed on scratch/distroless base images.

## Problem Background

The SBOM subsystem reads `container-factory-version` and `pm.lock` from the built image to generate CycloneDX purl metadata. The original code used `RunCommandInImage` (which executed `cat` inside a throwaway container) — this fails for scratch/distroless base images that ship no shell or coreutils.

The initial fix attempted to work around this by using stapel-embedded coreutils paths (`/.werf/stapel/embedded/bin/cat`) in the snapshot command. This works for the **build-time** part (packages stage) where the stapel build container provides a shell, but **does not** work for the **SBOM collection** part, because `RunCommandInImage` creates a container from the **built image** (scratch), which has no shell at all.

The correct solution splits the problem into two independent concerns:

1. **Build time** — write `container-factory-version` during the packages stage using shell commands that run in the build container (stapel provides shell + coreutils).
2. **SBOM collection** — read files from the built image without executing anything, by using the container backend's copy/mount API directly.

## User Scenarios

### Scenario: Build with PACKAGES_VERSION provided via werf build secrets (P1)

A user has `PACKAGES_VERSION` set in their CI environment and passes it via `--build-secret PACKAGES_VERSION=env:PACKAGES_VERSION`. Werf mounts the secret as a file at `/run/secrets/PACKAGES_VERSION` — the variable is **not** exported into the shell environment.

- **WHEN** the packages stage runs (container factory version snapshot + `pm sync`)
- **THEN** the shell script reads `PACKAGES_VERSION` from `/run/secrets/PACKAGES_VERSION` using stapel-embedded `cat` and exports it as a shell environment variable
- **AND** the `${PACKAGES_VERSION:?required by werf for pm SBOM provenance}` guard passes successfully
- **AND** the container factory version file (`/var/lib/pm/container-factory-version`) is written with the correct version
- **AND** `pm sync` inherits the exported `PACKAGES_VERSION` for SBOM purl generation

### Scenario: Build with REGISTRY provided via werf build secrets (P1)

A user has a custom registry URL set via `REGISTRY` and passes it via `--build-secret`.

- **WHEN** the packages stage runs
- **THEN** the shell script reads `REGISTRY` from `/run/secrets/REGISTRY` using stapel-embedded `cat` and exports it
- **AND** if `REGISTRY` is already set (e.g., via `ENV REGISTRY=...` in the base image), the existing value is preserved

### Scenario: Variables already set in base image (P1)

A user has `PACKAGES_VERSION` and/or `REGISTRY` already defined via `ENV` directives in the base image or via `docker run --env`.

- **WHEN** the packages stage runs
- **THEN** the existing environment variable values are preserved via `${VAR:-$(cat ...)}` shell parameter expansion
- **AND** the `/run/secrets/` files are not read (since the variables are already set)

### Scenario: Secrets not provided (P1)

A user does not use build secrets for `PACKAGES_VERSION` or `REGISTRY`.

- **WHEN** the packages stage runs
- **THEN** the `cat /run/secrets/...` commands silently fail (due to `2>/dev/null || true`)
- **AND** if the variables are also not set in the base image, the `${PACKAGES_VERSION:?required...}` guard catches the missing variable and fails the build with a clear error message

### Scenario: SBOM collection from scratch/distroless image (P2)

A user builds an image from a scratch or distroless base image and has SBOM generation enabled.

- **WHEN** the SBOM collector runs `CollectBOM` for the os-pm subsystem
- **THEN** it reads `pm.lock` and `container-factory-version` from the image using `ReadFileFromImage` (Docker copy API / Buildah mount) — no commands are executed inside the image
- **AND** the version file content is used as the `containerfactoryversion` purl qualifier
- **AND** the operation succeeds even though the image has no shell or coreutils

### Scenario: SBOM collection from regular image (P2)

A user builds an image from a regular base image (e.g., `ubuntu`, `alpine`).

- **WHEN** the SBOM collector runs
- **THEN** it reads the same files using `ReadFileFromImage` — the implementation is identical regardless of the image type
- **AND** the result is the same as before (backward compatible)

## Requirements

### R1: Build-time secret resolution before guard

The shell commands SHALL resolve `PACKAGES_VERSION` and `REGISTRY` from `/run/secrets/` **before** the `${PACKAGES_VERSION:?required...}` guard so that the guard sees the resolved values.

### R2: Non-destructive defaults

Each variable resolution SHALL use the shell parameter expansion pattern `${VAR:-$(<tool> /run/secrets/VAR 2>/dev/null || true)}`, which:
- Keeps the existing value if `VAR` is already set
- Reads from the secret file if `VAR` is unset
- Silently continues if the secret file does not exist

### R3: Stapel-embedded coreutils for build-time resolution

The shell commands SHALL use `stapel.CatBinPath()` and `stapel.MkdirBinPath()` so that `cat` and `mkdir` are available even when the packages stage runs on a scratch/distroless base image. The stapel volume is always mounted in the build container.

### R4: ReadFileFromImage for SBOM collection

The SBOM collector SHALL use `container_backend.ReadFileFromImage()` instead of `RunCommandInImage()` to read `pm.lock` and `container-factory-version` from the built image. This method:
- For Docker: creates a container without starting it, then streams the file via Docker's copy API
- For Buildah: mounts the container root filesystem and reads the file directly via `os.ReadFile`
- Requires no shell or coreutils in the target image

### R5: ReadFileFromImage covers both pm.lock and container-factory-version

The SBOM collector SHALL use `ReadFileFromImage` for both files it reads from the image:
- `collectPacketsFromLock` — reads `pm.lock`
- `readContainerFactoryVersion` — reads `container-factory-version`

### R6: No separate public API for secret resolution

The build-time resolution logic SHALL be an internal implementation detail of the `packages_commands.go` module — no new public Go functions or types are introduced.

### R7: Remove RunCommandInImage from container backend interface

The `RunCommandInImage` method SHALL be removed from the `ContainerBackend` interface and replaced with `ReadFileFromImage`, since no remaining code in the project uses command execution inside an image.

## Success Criteria

- **SC1**: When `PACKAGES_VERSION` is not in the shell environment but is available as `/run/secrets/PACKAGES_VERSION`, the packages stage exports it, the guard passes, and the version file is written.
- **SC2**: When `REGISTRY` is not in the shell environment but is available as `/run/secrets/REGISTRY`, the packages stage exports it.
- **SC3**: When both variables are already set, the secret file reads are skipped and existing values are preserved.
- **SC4**: When neither variable is set via environment or secrets, the guard fails with `${PACKAGES_VERSION:?required by werf for pm SBOM provenance}`.
- **SC5**: The generated shell command string contains `export PACKAGES_VERSION="${PACKAGES_VERSION:-$(/.werf/stapel/embedded/bin/cat /run/secrets/PACKAGES_VERSION 2>/dev/null || true)}"` and the equivalent for `REGISTRY`.
- **SC6**: The export commands appear before the `${PACKAGES_VERSION:?required...}` guard.
- **SC7**: The SBOM collector reads `pm.lock` and `container-factory-version` from a scratch-based image successfully via `ReadFileFromImage`.
- **SC8**: The SBOM collector reads the same files from a regular image successfully (backward compatibility).
- **SC9**: E2E test with scratch base image, pm and CA certs imported from a carrier image, and `PACKAGES_VERSION`/`REGISTRY` provided only as build secrets passes — the `containerfactoryversion` purl qualifier proves the secret value reached the provenance file.

## Assumptions

- Build secrets are provided by the CI system via werf's `--build-secret` flag and mounted by Buildah as files under `/run/secrets/<id>`.
- The `PACKAGES_VERSION` and `REGISTRY` secret IDs match the environment variable names they are meant to populate.
- The packages stage runs inside a build container that has the stapel volume mounted (providing shell and coreutils).
- The SBOM collector runs against the fully built image, not during the build.
- Docker copy API and Buildah mount API are available in the respective container backends.