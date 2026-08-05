# Feature Specification: Not Enforce pm Determinism

**Feature Branch**: `feat/config/not-enforce-pm-determinism`

**Created**: 2026-07-21

**Status**: Draft

**Input**: User description: "Необходимо: 1. Отсказаться от форсирования детерминизма для pm. 2. Вернуться к inline-синтаксису для pm"

## Project Context

**Delivery Kit** is a Go CLI tool for full-cycle CI/CD to Kubernetes. It is built on top of werf with Deckhouse Platform extensions. Key subsystems:

- **Build** (`pkg/build/`) — Container image building via Buildah
- **Config** (`pkg/config/`) — werf.yaml configuration parsing

The feature `006-enforce-pm-determinism` (previously migrated) replaced inline `os-pm` package declarations with a file-based spec+lock model using `pm.yaml` and `pm.lock` files. This specification describes reverting that change: restoring inline package syntax for `pm` and removing the file-based determinism enforcement.

The core reason for this revert is that OS-level package managers operate in a fundamentally different paradigm than language-specific package managers (e.g., `go-mod`, `python-uv`, `rust-cargo`). Unlike language ecosystems where lock files provide deterministic, reproducible builds across environments, OS-level PM implementations do not enforce determinism. Applying the file-based spec+lock model to `os-pm` was a mismatch with the OS package management paradigm.

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Declare OS packages inline (Priority: P1)

A user needs to install OS-level packages (`curl`, `jq`) in their build container. Instead of maintaining separate `pm.yaml` / `pm.lock` files, they declare packages inline in `werf.yaml`:

```yaml
packages:
  - type: os-pm
    spec:
      - curl==8.12.1
      - jq
```

Note: The `workdir` field is NOT configurable for `os-pm`. Packages are installed to the default system location.

**Why this priority**: This is the primary user flow — the core reason users interact with `os-pm`. OS-level package managers do not enforce determinism, so the file-based spec+lock model is not applicable. Inline syntax is the appropriate paradigm for OS package declarations.

**Independent Test**: A build directive with inline package list runs a single `pm install <pkg_1> <pkg_2> ...` command with all packages as arguments and installs them correctly in the container.

**Acceptance Scenarios**:

1. **Given** a `werf.yaml` with `packages: [{type: os-pm, spec: [curl==8.12.1, jq]}]`, **When** the build runs, **Then** a single `pm install curl==8.12.1 jq` command is executed
2. **Given** a `werf.yaml` with an `os-pm` directive having an empty `spec` list, **When** the config is parsed, **Then** a validation error is raised — `spec` must not be empty for `os-pm`

---

### User Story 2 - No pm packages needed (Priority: P2)

A user does not need any OS-level packages:

**Why this priority**: Important boundary case — ensures the system degrades gracefully when `os-pm` is not used.

**Independent Test**: A build without any `os-pm` directive produces no `pm install` commands and no os-pm SBOM processing.

**Acceptance Scenarios**:

1. **Given** a `werf.yaml` with no `packages` directive, **When** the build runs, **Then** no `pm install` or `pm sync` command is generated
2. **Given** a `werf.yaml` with a non-pm package type (e.g. `go-mod`), **When** the build runs, **Then** os-pm processing is skipped entirely

---

### Edge Cases

- What happens when a user specifies `workdir` in an `os-pm` directive? The configuration parser SHALL reject it with a validation error — `workdir` is not a valid field for `os-pm`.
- What happens when `spec` list contains invalid or non-existent package names? Current behavior should be preserved — `pm install curl==8.12.1 jq` reports the error and the build fails.
- What happens when `spec` list is empty? The configuration parser SHALL reject it with a validation error — `spec` must contain at least one package name for `os-pm`.
- What happens when a user has existing `pm.yaml`/`pm.lock` files in the project? They become inert — werf no longer reads them for os-pm processing.

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: Users SHALL be able to declare `os-pm` packages inline in `werf.yaml` using a `spec` list (e.g., `spec: [curl==8.12.1, jq]`) without requiring separate `pm.yaml`/`pm.lock` files
- **FR-002**: The system SHALL generate a single `pm install <pkg_1> <pkg_2> ...` command with all packages from the inline `spec` list as arguments, preserving version constraints (e.g., `pm install curl==8.12.1 jq`)
- **FR-003**: The system SHALL accept the `spec` field for `os-pm` as a list of package name strings (restoring the original YAML format), where each string may include version constraints (e.g., `curl==8.12.1`)
- **FR-004**: The build phase SHALL use a boolean flag to indicate whether os-pm packages are present, rather than passing a lock file path
- **FR-005**: SBOM collection for os-pm SHALL read `/var/lib/pm/index.json` (a file that `pm` maintains itself) via `ReadFileFromImage` and parse it to produce correct component data (names, versions, licenses, dependencies)
- **FR-006**: The `workdir` field SHALL NOT be configurable for `os-pm` directives. Packages are installed to the default system location without user-specified path overrides
- **FR-007**: An `os-pm` directive with an empty `spec` list SHALL be rejected at config validation — `spec` must contain at least one package name
- **FR-008**: The system SHALL generate a single unified command `PACKAGES_VERSION=... REGISTRY=... pm install <pkg_1> <pkg_2> ...` where the required environment variables (`PACKAGES_VERSION`, `REGISTRY`) are set inline for every invocation of `pm install`
- **FR-009**: All existing `pm.yaml`/`pm.lock` files in user projects SHALL be ignored by werf — no errors or unexpected behavior
- **FR-010**: Tests and test data SHALL be updated to match the inline package model (remove `pm.yaml`/`pm.lock` fixtures, restore old test expectations)
- **FR-011**: The system SHALL reject configurations where `spec` is specified simultaneously as both a list (inline package names) and a string (file path) for the same `os-pm` directive — this is ambiguous

### Go-Specific Requirements *(when applicable)*

- All public functions MUST accept `context.Context` as the first parameter
- Errors MUST be wrapped with `fmt.Errorf("doing something: %w", err)`
- Use `samber/lo` helpers (`lo.Filter`, `lo.Map`, `lo.Contains`, etc.) where appropriate
- Optional arguments use `<FunctionName>Options` struct — never functional options
- Add `var _ Interface = (*Impl)(nil)` compile-time check for each interface implementation

### Key Entities *(include if feature involves data)*

- **PackagesSpec**: Data structure holding `Packages []string` — the inline list of OS package names to install, mapped from the YAML `spec` key
- **OsPmDirective**: Configuration directive with an inline `spec` list (the `PackagesSpec`). The install target path is not user-configurable.
- **PmInstallCommand**: Generated shell command (`pm install <pkg_1> <pkg_2> ...`) with all packages from the inline `spec` list as arguments, prefixed with required environment variables

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: An `os-pm` directive with `spec: [curl==8.12.1, jq]` generates a single command `PACKAGES_VERSION=... REGISTRY=... pm install curl==8.12.1 jq`
- **SC-002**: An `os-pm` directive without `spec` is rejected at config validation — `spec` is required for `os-pm`
- **SC-003**: An `os-pm` directive does NOT accept a `workdir` field — specifying `workdir` is rejected at config validation
- **SC-004**: The SBOM for os-pm contains correct component data (names, versions, licenses, dependencies) for all installed packages
- **SC-005**: Existing `pm.yaml`/`pm.lock` files in user projects do NOT cause errors or unexpected behavior — they are simply ignored by werf
- **SC-006**: All existing unit and e2e tests pass after the revert

## Assumptions

- The `pm` binary is pre-installed in the builder image; werf does not install or manage it
- We interact with `pm` through its CLI commands (`pm install`, etc.) for package installation and read `/var/lib/pm/index.json` (maintained by `pm` itself) for SBOM state — we do not run capture commands or make assumptions about `pm`'s internal filesystem layout beyond its documented index file
- Users who adopted the file-based model will need to revert their `werf.yaml` configs to use inline syntax — no migration tool is provided
- The revert is source-code-only: the `006-enforce-pm-determinism` spec document remains as archived documentation
- The file-based spec+lock model (`pm.yaml`/`pm.lock`) was a misfit for `os-pm` because OS-level package managers do not enforce determinism — this differentiates `os-pm` from language-specific package ecosystems like `go-mod`, `python-uv`, and `rust-cargo`
- Legacy e2e fixtures with `pm.yaml`/`pm.lock` files will be removed as part of this revert