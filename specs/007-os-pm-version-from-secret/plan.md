# Implementation Plan: Resolve os-pm Version from Build Secrets

**Branch**: `fix/config/os-pm-version-from-secret` | **Date**: 2026-07-17 | **Spec**: `specs/007-os-pm-version-from-secret/spec.md`

**Input**: Reverse-engineered from the diff between `fix/config/os-pm-version-from-secret` and `origin/main` (commit `d66c0c3e5`).

**Note**: This plan is retroactively reconstructed from existing implementation.

## Summary

Add shell commands to the packages stage script that resolve `PACKAGES_VERSION` and `REGISTRY` environment variables from werf build secrets mounted as files under `/run/secrets/`. This ensures that when these variables are provided via `--build-secret` (which mounts files instead of exporting to the shell), they are available to the container factory version snapshot guard and the subsequent `pm sync` invocation.

## Technical Context

**Language/Version**: Go 1.24.10

**Primary Dependencies**:
- **Container building**: `containers/buildah` (werf fork: `werf/3p-buildah`), `containers/storage`, `containers/image`
- **SBOM**: `CycloneDX/cyclonedx-go`, `facebookincubator/nvdtools`
- **Utilities**: `samber/lo`, `werf/common-go`, `go-git/go-git`

**Secret mounting**: Buildah mounts secrets via `--secret id=<id>,env=<VAR>` or `--secret id=<id>,src=<path>`. The secret content becomes available as a file at `/run/secrets/<id>` inside the build container. This is the standard approach — secrets are NOT exported as environment variables automatically.

**Testing**: Ginkgo + Gomega for unit tests

**Target Platform**: Linux (amd64/arm64) via Buildah

## Constitution Check

N/A — feature already exists on its branch.

## Project Structure

### Documentation (this feature)

```text
specs/007-os-pm-version-from-secret/
├── spec.md              # This file (migrated)
├── plan.md              # This file (migrated)
└── tasks.md             # Task list (migrated)
```

### Source Code (changed files)

```text
pkg/config/
├── packages_commands.go          # Added resolvePmEnvFromSecrets constant, integrated into template
└── packages_commands_test.go     # New test file for ContainerFactoryVersionSnapshotCmd
```

## Complexity Tracking

| Violation | Why Needed | Simpler Alternative Rejected Because |
|-----------|------------|-------------------------------------|
| N/A | Feature is minimal and follows existing patterns | — |