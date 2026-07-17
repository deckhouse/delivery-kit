---
status: migrated
feature: os-pm-version-from-secret
created: 2026-07-17
source: branch fix/config/os-pm-version-from-secret
---

# Resolve os-pm Version from Build Secrets

## User Scenarios

### Scenario: Pass PACKAGES_VERSION via werf build secrets

A user has the `PACKAGES_VERSION` environment variable set in their CI system (e.g., GitLab CI, GitHub Actions) and passes it into the build via werf's `--build-secret` mechanism (e.g., `--build-secret PACKAGES_VERSION=env:PACKAGES_VERSION`). Werf mounts this secret as a file at `/run/secrets/PACKAGES_VERSION` inside the build container — the variable is **not** exported into the shell environment.

- **WHEN** the packages stage runs (container factory version snapshot + `pm sync`)
- **THEN** the shell script reads `PACKAGES_VERSION` from `/run/secrets/PACKAGES_VERSION` and exports it as a shell environment variable
- **AND** the `${PACKAGES_VERSION:?required by werf for pm SBOM provenance}` guard passes successfully
- **AND** the container factory version file (`/var/lib/pm/container-factory-version`) is written with the correct version
- **AND** `pm sync` inherits the exported `PACKAGES_VERSION` for SBOM purl generation

### Scenario: Pass REGISTRY via werf build secrets

A user has a custom container registry URL set via the `REGISTRY` environment variable and passes it via werf build secrets.

- **WHEN** the packages stage runs
- **THEN** the shell script reads `REGISTRY` from `/run/secrets/REGISTRY` and exports it as a shell environment variable
- **AND** if `REGISTRY` is already set (e.g., via `ENV REGISTRY=...` in the base image), the existing value is preserved

### Scenario: Variables already set in base image

A user has `PACKAGES_VERSION` and/or `REGISTRY` already defined via `ENV` directives in the base image or via the `docker run --env` mechanism.

- **WHEN** the packages stage runs
- **THEN** the existing environment variable values are preserved
- **AND** the `/run/secrets/` files are not read (since the variables are already set)

### Scenario: Secrets not provided

A user does not use build secrets for `PACKAGES_VERSION` or `REGISTRY`.

- **WHEN** the packages stage runs
- **THEN** the `cat /run/secrets/...` commands silently fail (due to `2>/dev/null || true`)
- **AND** if the variables are also not set in the base image, the `${PACKAGES_VERSION:?required...}` guard catches the missing variable and fails the build with a clear error message

## Requirements

### R1: Secret resolution before guard

The `resolvePmEnvFromSecrets` shell commands SHALL be emitted **before** the `${PACKAGES_VERSION:?required...}` guard so that the guard sees the resolved values.

### R2: Non-destructive defaults

Each variable resolution SHALL use the shell parameter expansion pattern `${VAR:-$(cat /run/secrets/VAR 2>/dev/null || true)}`, which:
- Keeps the existing value if `VAR` is already set
- Reads from the secret file if `VAR` is unset
- Silently continues if the secret file does not exist

### R3: Coverage of both PACKAGES_VERSION and REGISTRY

Both `PACKAGES_VERSION` and `REGISTRY` SHALL be resolved from build secrets using the same pattern.

### R4: Integration into snapshot command template

The `resolvePmEnvFromSecrets` commands SHALL be prepended to the `containerFactoryVersionSnapshotCmdTmpl` so that every invocation of the snapshot command (and by extension `pm sync`) sees the resolved variables.

### R5: No separate public API

The resolution logic SHALL be an internal implementation detail of the `packages_commands.go` module — no new public Go functions or types are introduced.

## Success Criteria

- **SC1**: When `PACKAGES_VERSION` is not in the shell environment but is available as `/run/secrets/PACKAGES_VERSION`, the snapshot command exports it and the guard passes.
- **SC2**: When `REGISTRY` is not in the shell environment but is available as `/run/secrets/REGISTRY`, the snapshot command exports it.
- **SC3**: When both variables are already set, the secret file reads are skipped and existing values are preserved.
- **SC4**: When neither variable is set via environment or secrets, the guard fails with `${PACKAGES_VERSION:?required by werf for pm SBOM provenance}`.
- **SC5**: The generated shell command string contains `export PACKAGES_VERSION="${PACKAGES_VERSION:-$(cat /run/secrets/PACKAGES_VERSION 2>/dev/null || true)}"` and the equivalent for `REGISTRY`.
- **SC6**: The export commands appear before the `${PACKAGES_VERSION:?required...}` guard in the generated command string.

## Assumptions

- Build secrets are provided by the CI system via werf's `--build-secret` flag and mounted by Buildah as files under `/run/secrets/<id>`.
- The `PACKAGES_VERSION` and `REGISTRY` secret IDs match the environment variable names they are meant to populate.
- The container factory version file (`/var/lib/pm/container-factory-version`) is consumed by the SBOM subsystem for purl generation.