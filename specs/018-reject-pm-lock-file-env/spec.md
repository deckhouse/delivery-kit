# Feature Specification: reject PM_LOCK_FILE override

**Feature Branch**: `018-reject-pm-lock-file-env`

**Created**: 2026-08-20

**Status**: Draft

**Input**: User description: "DK читает состояние SBOM для pm из файла внутри контейнера по фиксированному пути /var/lib/pm/index.json (это умолчание). Переменная PM_LOCK_FILE переопределяет этот путь. Это создает риск неполноты SBOM применительно к pm. Решение: на уровне валидации конфигурации отклонять использование переменной окружения PM_LOCK_FILE, чтобы избежать риска неполноты SBOM применительно к pm в этом случае."

## Project Context

**Delivery Kit** is a Go CLI tool for full-cycle CI/CD to Kubernetes. It is built on top of werf with Deckhouse Platform extensions. Key subsystems:

- **Build** (`pkg/build/`) — Container image building via Buildah
- **Deploy** (`pkg/deploy/`) — Kubernetes deployment via werf/nelm (Helm-based)
- **SBOM** (`pkg/sbom/`) — Software Bill of Materials generation and validation
- **Config** (`pkg/config/`) — werf.yaml configuration parsing and validation

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Reject an SBOM-breaking PM path override (Priority: P1)

A user configures OS packages managed by `pm`. The delivery process must prevent the package manager from directing its state file away from the path used by SBOM collection, because doing so can make the generated SBOM incomplete.

**Why this priority**: Preventing an incomplete SBOM is a correctness and supply-chain safety requirement. The invalid configuration must be stopped before any build work starts.

**Independent Test**: Validate a configuration containing `PM_LOCK_FILE` for `os-pm` and verify that validation fails with an actionable error; validate an equivalent configuration without the variable and verify that it remains accepted.

**Acceptance Scenarios**:

1. **Given** a valid `os-pm` configuration with `PM_LOCK_FILE` set to any value, **When** configuration validation runs, **Then** it rejects the configuration before the build starts and identifies `PM_LOCK_FILE` as unsupported.
2. **Given** a valid `os-pm` configuration without `PM_LOCK_FILE`, **When** configuration validation runs, **Then** the configuration is accepted and the SBOM state remains associated with `/var/lib/pm/index.json`.
3. **Given** a configuration for a package type other than `os-pm` that sets an unrelated environment variable, **When** configuration validation runs, **Then** the unrelated configuration is not rejected by this feature.

---

### User Story 2 - Preserve the fixed SBOM source path (Priority: P1)

A user or CI system needs a predictable SBOM result for `pm`. The package manager state used for SBOM collection must continue to be read from `/var/lib/pm/index.json` inside the built image, with no configuration-supported override.

**Why this priority**: A single authoritative path ensures that all installed `pm` packages are visible to SBOM collection and prevents silent omissions caused by alternate state files.

**Independent Test**: Run validation and SBOM collection for an accepted `os-pm` configuration and verify that the documented and effective source is `/var/lib/pm/index.json`; verify that a custom path cannot be enabled through configuration.

**Acceptance Scenarios**:

1. **Given** an accepted `os-pm` configuration, **When** the SBOM is collected, **Then** the `pm` state is read from `/var/lib/pm/index.json` inside the image.
2. **Given** a configuration attempting to set `PM_LOCK_FILE` to the default path explicitly, **When** validation runs, **Then** it is still rejected because the environment variable itself is unsupported.
3. **Given** a configuration attempting to set `PM_LOCK_FILE` to an empty value, **When** validation runs, **Then** it is rejected rather than treated as an opt-out of the restriction.

---

### Edge Cases

- The check applies whether `PM_LOCK_FILE` is set to a custom path, the default path, a relative path, or an empty value.
- The check applies before build commands, package installation, or SBOM collection are executed.
- The error identifies the unsupported variable and explains that `pm` SBOM data must remain at `/var/lib/pm/index.json`.
- Other environment variables used by `os-pm`, including variables supported for registry access, remain governed by their existing validation and behavior.
- Configurations that do not use `os-pm` are unaffected unless they independently violate an existing configuration rule.

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: Configuration validation MUST reject any `os-pm` environment declaration containing the variable `PM_LOCK_FILE`.
- **FR-002**: The rejection MUST occur during configuration validation, before build commands, package installation, or SBOM collection begin.
- **FR-003**: The rejection MUST be independent of the value assigned to `PM_LOCK_FILE`, including custom paths, `/var/lib/pm/index.json`, relative paths, and an empty value.
- **FR-004**: The validation error MUST name `PM_LOCK_FILE` and explain that overriding the `pm` state path is unsupported because SBOM collection requires the complete state from `/var/lib/pm/index.json`.
- **FR-005**: For accepted `os-pm` configurations, the only supported `pm` state path for SBOM collection MUST remain `/var/lib/pm/index.json` inside the built image.
- **FR-006**: The feature MUST NOT reject unrelated environment variables or alter their existing behavior.
- **FR-007**: The feature MUST NOT change behavior for configurations that do not use `os-pm`, except where an existing shared validation rule already applies.
- **FR-008**: Automated validation coverage MUST include rejection of non-empty, default-path, and empty `PM_LOCK_FILE` values, acceptance of an `os-pm` configuration without the variable, and preservation of unrelated environment variables.

### Key Entities *(include if feature involves data)*

- **OS-PM configuration**: A package-manager configuration that may contain environment variables used during `pm` operations.
- **PM_LOCK_FILE**: A prohibited environment variable that changes the location of the `pm` state file and can cause incomplete SBOM data.
- **PM runtime index**: The authoritative state at `/var/lib/pm/index.json` inside the built image, from which `pm` SBOM components are collected.
- **Configuration validation error**: The actionable error returned before build execution when the prohibited variable is present.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: 100% of configurations containing `PM_LOCK_FILE`, regardless of its value, are rejected during validation before any build command executes.
- **SC-002**: 100% of accepted `os-pm` configurations collect `pm` SBOM state from `/var/lib/pm/index.json`; no accepted configuration can select another path through `PM_LOCK_FILE`.
- **SC-003**: A validation error for the prohibited variable names `PM_LOCK_FILE` and `/var/lib/pm/index.json`, allowing a user to identify and correct the issue without inspecting build logs.
- **SC-004**: Existing configurations without `PM_LOCK_FILE` continue to validate successfully, and unrelated supported `os-pm` environment variables retain their prior behavior.
- **SC-005**: Automated tests cover at least the three prohibited value classes (custom, default, and empty) plus the accepted no-variable case.

## Assumptions

- `PM_LOCK_FILE` is supplied through the environment configuration associated with an `os-pm` package declaration.
- `/var/lib/pm/index.json` is the fixed and supported runtime state path for `pm` SBOM collection; changing it is out of scope.
- No compatibility mode or warning-only mode is required; every occurrence of `PM_LOCK_FILE` is a configuration error.
- Existing validation for other environment variables and package types remains unchanged.
- Users who currently rely on `PM_LOCK_FILE` must remove it and use the supported default state path; no migration or automatic rewrite is provided.
