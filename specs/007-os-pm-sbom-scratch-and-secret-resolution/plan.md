# Implementation Plan: SBOM Scratch Compatibility and Build Secret Resolution for os-pm

**Branch**: `fix/pm-snapshot-stapel-tool-paths` | **Date**: 2026-07-20 | **Spec**: `specs/007-os-pm-sbom-scratch-and-secret-resolution/spec.md`

**Revision**: 2 — rethinking after the initial fix (using stapel coreutils paths) failed on scratch/distroless base images.

**Input**: Reverse-engineered from the diff between `fix/pm-snapshot-stapel-tool-paths` and `origin/main` (commits `6a744aaf6` through `ea95e3c7e`).

**Note**: This plan is retroactively reconstructed from existing implementation. The original spec was migrated from `fix/config/os-pm-version-from-secret`, then rethought on `fix/pm-snapshot-stapel-tool-paths`.

## Summary

The problem had two independent parts that were conflated in the initial approach:

1. **Build-time (packages stage)**: The `PACKAGES_VERSION` and `REGISTRY` variables must be resolved from werf build secrets (mounted as files under `/run/secrets/`) and written to `container-factory-version` during the build. This is done via shell commands that run in the build container, which has the stapel volume mounted (providing shell + coreutils). The initial fix's use of `stapel.CatBinPath()` and `stapel.MkdirBinPath()` is correct for this part.

2. **SBOM collection (runtime after build)**: The SBOM collector reads `pm.lock` and `container-factory-version` from the **already-built** image. The original approach used `RunCommandInImage` which creates a throwaway container from the built image and runs `cat` inside it. This fails for scratch/distroless images because the throwaway container has no shell. The correct fix is to replace `RunCommandInImage` with `ReadFileFromImage`, which reads files directly via Docker copy API (for Docker backend) or Buildah mount (for Buildah backend) — no execution needed.

## Technical Context

**Language/Version**: Go 1.24.10

**Primary Dependencies**:
- **Container building**: `containers/buildah` (werf fork: `werf/3p-buildah`), `containers/storage`, `containers/image`
- **SBOM**: `CycloneDX/cyclonedx-go`, `facebookincubator/nvdtools`
- **Utilities**: `samber/lo`, `werf/common-go`, `go-git/go-git`
- **Docker API**: `docker/docker` (for `CopyFromContainer`)

**Secret mounting**: Buildah mounts secrets via `--secret id=<id>,env=<VAR>` or `--secret id=<id>,src=<path>`. The secret content becomes available as a file at `/run/secrets/<id>` inside the build container. This is the standard approach — secrets are NOT exported as environment variables automatically.

**Build-time resolution**: The packages stage runs inside a build container that has the stapel volume mounted at `/.werf/stapel/embedded/bin/`, providing `cat`, `mkdir`, and a shell. The shell commands in `ContainerFactoryVersionSnapshotCmd()` are prepended to the packages stage script via `imageBase.Shell.Packages`.

**ReadFileFromImage**: Two implementations:
- **Docker**: Creates a container without starting it (`docker create`), then uses `docker cp` (Docker API `CopyFromContainer`) to stream the file as a tar archive. Parses the tar to extract the file content.
- **Buildah**: Creates a container, mounts its root filesystem via Buildah's mount API, and reads the file directly with `os.ReadFile`. Unmounts after reading.

**Testing**: Ginkgo + Gomega for unit tests; Ginkgo for e2e tests

**Target Platform**: Linux (amd64/arm64) via Buildah

## Constitution Check

N/A — feature already exists on its branch.

## Project Structure

### Documentation (this feature)

```text
specs/007-os-pm-sbom-scratch-and-secret-resolution/spec.md
├── spec.md              # This file (migrated, revision 2)
├── plan.md              # This file (migrated, revision 2)
└── tasks.md             # Task list (migrated, revision 2)
```

### Source Code (changed files)

```text
pkg/config/
├── packages_commands.go                  # Added resolvePmEnvFromSecrets() function, 
│                                         # integrated into ContainerFactoryVersionSnapshotCmd()
│                                         # Uses stapel.CatBinPath() and stapel.MkdirBinPath()
└── packages_commands_test.go             # Unit tests for ContainerFactoryVersionSnapshotCmd

pkg/container_backend/
├── interface.go                          # Replaced RunCommandInImage with ReadFileFromImage
├── buildah_backend.go                    # ReadFileFromImage: mount + os.ReadFile
├── docker_server_backend.go              # ReadFileFromImage: docker create + docker cp (tar)
└── perf_check_container_backend.go       # Delegates to underlying backend

pkg/docker/
└── container.go                          # Added ContainerCopyFrom helper

pkg/sbom/packages/os_pm/
└── collect.go                            # Replaced RunCommandInImage with ReadFileFromImage
                                         # for both pm.lock and container-factory-version

test/mock/
└── container_backend.go                  # Regenerated mocks for ReadFileFromImage

test/e2e/sbom/
├── _fixtures/inject/ospm_scratch_secrets/  # E2E test fixtures for scratch base image
└── packages_test.go                       # E2E test for os-pm scratch secrets
```

## Complexity Tracking

| Violation | Why Needed | Simpler Alternative Rejected Because |
|-----------|------------|-------------------------------------|
| N/A | Feature is minimal and follows existing patterns | — |