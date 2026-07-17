# Tasks: Resolve os-pm Version from Build Secrets

**Input**: Migrated from commit `d66c0c3e5` on branch `fix/config/os-pm-version-from-secret`.

**Prerequisites**: None — all tasks are completed.

## Phase 1: Add Secret Resolution to Packages Commands

- [x] T001 Add `resolvePmEnvFromSecrets` shell constant to `pkg/config/packages_commands.go` with `export` commands for `PACKAGES_VERSION` and `REGISTRY` using the `${VAR:-$(cat /run/secrets/VAR 2>/dev/null || true)}` pattern
- [x] T002 Integrate `resolvePmEnvFromSecrets` into `containerFactoryVersionSnapshotCmdTmpl` by prepending it before the `${PACKAGES_VERSION:?required...}` guard

## Phase 2: Tests

- [x] T003 Create `pkg/config/packages_commands_test.go` with Ginkgo tests for `ContainerFactoryVersionSnapshotCmd`:
  - Verifies the hard PACKAGES_VERSION guard is preserved
  - Verifies the snapshot is written to the container-factory-version file
  - Verifies `PACKAGES_VERSION` and `REGISTRY` are resolved from `/run/secrets/`
  - Verifies exports appear before the guard