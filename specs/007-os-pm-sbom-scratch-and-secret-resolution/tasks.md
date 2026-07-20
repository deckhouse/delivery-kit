# Tasks: SBOM Scratch Compatibility and Build Secret Resolution for os-pm

**Input**: Migrated from commits `6a744aaf6` through `ea95e3c7e` on branches `fix/config/os-pm-version-from-secret` and `fix/pm-snapshot-stapel-tool-paths`.

**Revision**: 2 — rethinking after the initial fix (stapel coreutils paths) failed on scratch/distroless base images.

**Prerequisites**: None — all tasks are completed.

## Phase 1: Build-time Secret Resolution

The packages stage needs to write `container-factory-version` during the build. Secret values are mounted as files under `/run/secrets/` by Buildah. Shell commands using stapel-embedded coreutils are prepended to the packages stage script.

- [x] **T001** Add `resolvePmEnvFromSecrets()` function to `pkg/config/packages_commands.go` that generates shell `export` commands for `PACKAGES_VERSION` and `REGISTRY` using `${VAR:-$(<cat> /run/secrets/VAR 2>/dev/null || true)}` pattern with `stapel.CatBinPath()` for the `cat` binary
- [x] **T002** Integrate `resolvePmEnvFromSecrets()` into `ContainerFactoryVersionSnapshotCmd()` by prepending it before the `${PACKAGES_VERSION:?required...}` guard — uses `stapel.MkdirBinPath()` for `mkdir -p`
- [x] **T003** Wire `ContainerFactoryVersionSnapshotCmd()` into `GeneratePackagesCommands()` so that the snapshot command is emitted when an os-pm package directive is present and SBOM is enabled

## Phase 2: Replace RunCommandInImage with ReadFileFromImage (SBOM collection)

The SBOM collector reads `pm.lock` and `container-factory-version` from the built image. `RunCommandInImage` fails for scratch/distroless images because they have no shell. Replace with `ReadFileFromImage` which reads files directly via Docker copy API or Buildah mount.

- [x] **T004** Replace `RunCommandInImage` with `ReadFileFromImage` in the `ContainerBackend` interface in `pkg/container_backend/interface.go`:
  - New signature: `ReadFileFromImage(ctx, imageRef, path string, opts ReadFileFromImageOpts) ([]byte, error)`
  - Remove `RunCommandInImage` and `RunCommandInImageOpts`
  - Add `ReadFileFromImageOpts` (alias for `CommonOpts`)
- [x] **T005** Implement `ReadFileFromImage` for Docker backend in `pkg/container_backend/docker_server_backend.go`:
  - Create a container without starting it (`docker create`)
  - Copy the file from the container via `docker cp` (Docker API `CopyFromContainer`)
  - Parse the tar stream to extract the file content
  - Remove the container after reading
- [x] **T006** Implement `ReadFileFromImage` for Buildah backend in `pkg/container_backend/buildah_backend.go`:
  - Create a container
  - Mount the container's root filesystem via Buildah mount API
  - Read the file directly via `os.ReadFile`
  - Unmount and remove the container after reading
- [x] **T007** Update `PerfCheckContainerBackend` in `pkg/container_backend/perf_check_container_backend.go` to delegate `ReadFileFromImage` to the underlying backend
- [x] **T008** Add `ContainerCopyFrom` helper function in `pkg/docker/container.go` that wraps `apiCli().CopyFromContainer()`
- [x] **T009** Update SBOM collector in `pkg/sbom/packages/os_pm/collect.go`:
  - Replace `containerBackend.RunCommandInImage(ctx, imageRef, []string{"cat", lockPath}, ...)` with `containerBackend.ReadFileFromImage(ctx, imageRef, lockPath, ...)`
  - Replace `containerBackend.RunCommandInImage(ctx, imageRef, []string{"cat", config.ContainerFactoryVersionFile}, ...)` with `containerBackend.ReadFileFromImage(ctx, imageRef, config.ContainerFactoryVersionFile, ...)`
- [x] **T010** Regenerate mocks in `test/mock/container_backend.go` — replace `RunCommandInImage` with `ReadFileFromImage`

## Phase 3: Tests

- [x] **T011** Unit tests in `pkg/config/packages_commands_test.go` for `ContainerFactoryVersionSnapshotCmd`:
  - Verifies the hard PACKAGES_VERSION guard is preserved
  - Verifies the snapshot is written to the container-factory-version file
  - Verifies stapel-embedded coreutils paths are used (not plain `cat`/`mkdir`)
  - Verifies `PACKAGES_VERSION` and `REGISTRY` are resolved from `/run/secrets/`
  - Verifies exports appear before the guard
- [x] **T012** E2E test in `test/e2e/sbom/packages_test.go` with fixtures in `test/e2e/sbom/_fixtures/inject/ospm_scratch_secrets/`:
  - Builds an image from `registry.werf.io/werf/scratch` base image
  - Imports pm and CA certs from a carrier image
  - Provides `PACKAGES_VERSION` and `REGISTRY` only as build secrets (no shell env)
  - Asserts the `containerfactoryversion` purl qualifier proves the secret value reached the provenance file
  - Fails unless the snapshot command resolves secrets via stapel-embedded tools AND the SBOM collector reads files via `ReadFileFromImage`

## Known Gaps

- None identified. The unit tests cover the command string generation, and the e2e test covers the full scratch-base-image scenario end-to-end, including both build-time secret resolution and SBOM collection via `ReadFileFromImage`.