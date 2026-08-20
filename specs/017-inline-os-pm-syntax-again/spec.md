# Feature Specification: inline os-pm syntax again

**Feature Branch**: `017-inline-os-pm-syntax-again`

**Created**: 2026-08-13

**Status**: Draft

**Input**: User description: "Необходимо вернуть inline syntax для pm, отменив часть из ранее сделанных изменений specs/015-enforce-pm-determinism-again. Основные критерии: - используется inline syntax для pm - секций os-pm в packages может быть несколько - после выполнения всех команд pm в образе, итогое состояние читается из файла в образе /var/lib/pm/index.json и на его основе формируется SBOM - рабочая директория (workdir) для pm не используется"

## Project Context

**Delivery Kit** is a Go CLI tool for full-cycle CI/CD to Kubernetes. It is built on top of werf with Deckhouse Platform extensions. Key subsystems:

- **Build** (`pkg/build/`) — Container image building via Buildah
- **Config** (`pkg/config/`) — werf.yaml configuration parsing
- **SBOM** (`pkg/sbom/`) — Software Bill of Materials generation and validation

The `os-pm` package type (OS package manager — apt, apk, yum, etc.) went through several iterations:

1. **006-enforce-pm-determinism** — Introduced file-based `pm.yaml`/`pm.lock` syntax.
2. **009-not-enforce-pm-determinism** — Reverted to inline syntax (spec as list of strings in `werf.yaml`), reading SBOM from `/var/lib/pm/index.json` inside the built image.
3. **015-enforce-pm-determinism-again** — Re-introduced file-based `pm.yaml`/`pm.lock` syntax as the *only* supported syntax, with SBOM from `pm.lock` in the build context.

The 015 approach enforced a deterministic lock-file model that required users to maintain `pm.yaml` and `pm.lock` files in their repository. This specification describes reverting to inline syntax while preserving the ability to have **multiple `os-pm` sections** in packages. The SBOM is read from the final state file `/var/lib/pm/index.json` inside the built image after all pm commands have executed, which naturally handles multiple os-pm sections without needing to reconcile lock files.

## Clarifications

### Session 2026-08-13

- Q: What is the exact command that the `pm` binary accepts to install packages from an inline list? → A: `pm install <pkg_1> <pkg_2> ...` — accepts multiple packages and version constraints as arguments (e.g., `pm install curl==8.12.1 jq`).
- Q: Is the `containerFactoryVersion` PURL qualifier always present, and where does its value come from? → A: Yes, the `containerFactoryVersion` qualifier MUST always be present in the PURL. The value comes from either (1) the `PACKAGES_VERSION` environment variable or (2) the `/var/lib/pm/container-factory-version` file inside the image.

## User Scenarios & Testing *(mandatory)*

### User Story 1 — Declare OS packages inline, multiple sections (Priority: P1)

A user building a container image needs to install OS-level packages. They declare packages inline in `werf.yaml` as a list of strings. The user may need multiple `os-pm` sections to install packages from different sources or with different environment variables:

```yaml
packages:
  - type: os-pm
    spec:
      - curl==8.12.1
      - jq
  - type: os-pm
    spec:
      - custom-pkg==2.0.0
    env:
      REGISTRY: internal-registry.example.com
```

Each `os-pm` section generates a separate pm command. The final SBOM is produced from the single `/var/lib/pm/index.json` file that reflects the combined state after all commands execute.

**Why this priority**: This is the primary user flow — the core reason users interact with `os-pm`. Inline syntax is the natural paradigm for OS-level packages, and multiple sections provide flexibility for different package sources.

**Independent Test**: A build directive with two `os-pm` sections runs two pm commands and produces a single SBOM containing all packages from both sections.

**Acceptance Scenarios**:

1. **Given** a `werf.yaml` with `packages: [{type: os-pm, spec: [curl==8.12.1, jq]}]`, **When** the build runs, **Then** a single `pm install curl==8.12.1 jq` command is executed (with env vars passed inline).
2. **Given** a `werf.yaml` with two `os-pm` sections, **When** the build runs, **Then** two separate pm commands are executed, one per section.
3. **Given** a `werf.yaml` with two `os-pm` sections, each with different `env` variables, **When** the build runs, **Then** each pm command is prefixed with its respective environment variables.

---

### User Story 2 — SBOM from final state in image (Priority: P1)

After all pm commands execute in the build container, the system reads `/var/lib/pm/index.json` from inside the built image. This file contains the combined state of all OS packages installed by all pm commands. The SBOM is formed based on this single file.

**Why this priority**: The SBOM is a mandatory output of the build. Reading the final state from the image naturally handles multiple os-pm sections without file reconciliation.

**Independent Test**: A build with two `os-pm` sections produces a single CycloneDX SBOM containing all packages from both sections, with correct names, versions, licenses, and dependencies.

**Acceptance Scenarios**:

1. **Given** a build with `os-pm` packages, **When** the build completes, **Then** the SBOM contains all packages from `/var/lib/pm/index.json` with correct names, versions, and licenses.
2. **Given** a build with two `os-pm` sections, **When** the build completes, **Then** the SBOM contains packages from both sections merged into a single component list.
3. **Given** a build with `os-pm` packages, **When** the SBOM is generated, **Then** the `containerFactoryVersion` PURL qualifier is set on each os-pm component. The value comes from either the `PACKAGES_VERSION` environment variable or the `/var/lib/pm/container-factory-version` file inside the image.

---

### User Story 3 — No os-pm packages needed (Priority: P2)

A user does not need any OS-level packages.

**Why this priority**: Important boundary case — ensures the system degrades gracefully when `os-pm` is not used.

**Independent Test**: A build without any `os-pm` directive produces no pm commands and no os-pm SBOM processing.

**Acceptance Scenarios**:

1. **Given** a `werf.yaml` with no `packages` directive, **When** the build runs, **Then** no pm command is generated.
2. **Given** a `werf.yaml` with a non-`os-pm` package type (e.g., `go-mod`), **When** the build runs, **Then** os-pm processing is skipped entirely.

---

### Edge Cases

- What happens when `workdir` is specified for `os-pm`? The configuration parser SHALL reject it with a validation error — `workdir` is not applicable for OS-level package managers.
- What happens when `spec` is not a list of strings (e.g., a string path)? The configuration parser SHALL reject it — `spec` for `os-pm` must be a list of package name strings, not a file path.
- What happens when `spec` is empty? The configuration parser SHALL reject it — `spec` must contain at least one package name.
- What happens when `spec` contains invalid package names or versions? The `pm install` command reports the error and the build fails — consistent with existing behavior.
- What happens when `/var/lib/pm/index.json` does not exist in the built image? This is an invalid image state: the collector SHALL return an error because the runtime index is mandatory whenever os-pm processing is enabled.
- What happens when `/var/lib/pm/index.json` is empty or malformed? The build SHALL fail with a descriptive error indicating that the pm index file could not be parsed.
- What happens when `env` is specified alongside inline `spec`? The `env` field works as before — environment variables are passed to the `pm install` command.
- What happens when `/var/lib/pm/container-factory-version` cannot be read? The collector SHALL keep the existing error contract, write the read error to debug logging with image/path context, and SHALL NOT read `PACKAGES_VERSION` from the host process as a fallback. The qualifier is populated only when the persisted image file is read successfully.
- What happens when a user has existing `pm.yaml`/`pm.lock` files in the project from the 015 approach? They become inert — werf no longer reads them for os-pm processing. The package declarations are now in the `spec` list in `werf.yaml`.
- What happens when the external refs server returns an error while resolving PURLs of os-pm components? The build SHALL fail with an aggregated, hierarchical error — consistent with the behavior established in 015-enforce-pm-determinism-again.

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: Users SHALL be able to declare `os-pm` packages inline in `werf.yaml` using a `spec` list of strings (e.g., `spec: [curl==8.12.1, jq]`), restoring the original YAML format. This is the **only** supported syntax for `os-pm` — file-based `spec` (string path to a manifest file) is NOT supported.
- **FR-002**: Multiple `os-pm` sections SHALL be allowed in the `packages` list. Each section generates its own pm command. All sections are processed independently during the build phase, and the SBOM is produced from the final combined state.
- **FR-003**: The `spec` field for `os-pm` SHALL be required and MUST contain at least one package name. An empty `spec` list SHALL be rejected at config validation.
- **FR-004**: The `workdir` field SHALL NOT be accepted for `os-pm` — specifying `workdir` SHALL produce a validation error. OS-level package managers operate at the system level, not per-project.
- **FR-005**: The `env` field for `os-pm` SHALL continue to work as established in `012-os-pm-env-vars` — environment variables are passed as inline prefixes to the pm command.
- **FR-006**: The install command for `os-pm` SHALL be `pm install <pkg_1> ... <pkg_N>` (with all packages from the inline `spec` list as arguments), preceded by the container factory version preamble (`mkdir -p /var/lib/pm`, write `PACKAGES_VERSION` to `/var/lib/pm/container-factory-version`). Required environment variables (`PACKAGES_VERSION`, `REGISTRY`) are set inline.
- **FR-007**: The SBOM collector for `os-pm` SHALL read `/var/lib/pm/index.json` from inside the built image via `ReadFileFromImage` and parse it using delivery-kit's own parser code to extract component metadata (names, versions, licenses, dependencies). This is the **only** source of os-pm package data for the SBOM.
- **FR-008**: The `containerFactoryVersion` PURL qualifier SHALL be read from `/var/lib/pm/container-factory-version` inside the built image. The collector SHALL NOT use a host `PACKAGES_VERSION` fallback. If reading the version file fails, the error SHALL be written to debug logging with image/path context while the collector preserves the agreed collection error behavior.
- **FR-009**: The `ParsePmInstalledJSON` and `ConvertToCycloneDX` functions SHALL be reused for parsing `/var/lib/pm/index.json` and converting to CycloneDX format.
- **FR-010**: The build phase SHALL use a boolean or getter (`HasOSPMPackages()`) to indicate whether os-pm packages are present, rather than passing a lock file path. The `OSPMLockPath()` method from 015 SHALL be removed.
- **FR-011**: The `PMBOMPatcher` from 015 (which reads `pm.lock` from the git repository) SHALL be removed. Its functionality is replaced by reading `/var/lib/pm/index.json` from the built image.
- **FR-012**: The `managedinput` buildResolvers SHALL continue to skip syft cataloger derivation for `os-pm` — delivery-kit handles os-pm SBOM collection directly via its own code.
- **FR-013**: The `PackagesDirective` SHALL support inline package lists (spec as `[]string`) alongside or instead of `FileBasedSpec` for the `os-pm` type. The `FileBasedSpec`/`file-based` config path for `os-pm` SHALL be removed.
- **FR-014**: The `fillFileBasedSpec` special-cased handling for `os-pm` SHALL be removed. The `os-pm` type SHALL NOT use `FileBasedSpec` resolution.
- **FR-015**: The `ecosystems` entry for `os-pm` SHALL be updated: `DefaultSpecFile` and `DefaultLockFile` SHALL be empty (not applicable to inline syntax), `InstallCmd` SHALL use `pm install <pkgs>` instead of `pm sync --from <lockfile>`, and `CatalogerName` SHALL be set to a value appropriate for the runtime-index cataloger (e.g., `"pm-cataloger"`).
- **FR-016**: The `spec` YAML field for `os-pm` SHALL accept a list of strings (package names), not a string (file path). The config parser SHALL distinguish between `os-pm` (list of strings) and other types (string path).
- **FR-017**: All existing unit tests and test data that were updated in 015 to use file-based `pm.yaml`/`pm.lock` syntax SHALL be updated to use inline `spec` list syntax. The collection tests SHALL also cover the mandatory runtime index, debug logging for version-read errors, and the absence of a host fallback. This includes:
  - `pkg/config/raw_packages_directive_test.go` — restore tests for inline `os-pm` spec list parsing
  - `pkg/config/packages_directive_javascript_test.go` — restore combined config tests with inline `os-pm`
  - `pkg/config/packages_commands_test.go` — restore `pm install` command generation tests
  - `pkg/sbom/managedinput/managedinput_test.go` — update tests for inline `os-pm` directives
  - `pkg/build/stage/packages_test.go` — update if referencing file-based os-pm
- **FR-018**: All e2e test fixtures that were migrated in 015 to use `pm.yaml`/`pm.lock` files SHALL be reverted to use inline `spec` list syntax. The `pm.yaml` and `pm.lock` files SHALL be removed from fixture directories.

### Key Entities *(include if feature involves data)*

- **PackagesSpec**: Data structure holding `Packages []string` — the inline list of OS package names to install, mapped from the YAML `spec` key. This is the only valid format for `os-pm`.
- **OsPmDirective**: Configuration directive with inline `spec` list (package names), optional `env` variables. The `workdir` field is not applicable.
- **PmInstallCommand**: Generated shell command (`pm install <pkg_1> <pkg_2> ...`) with all packages from the inline `spec` list as arguments, preceded by the container factory version preamble and environment variables.
- **/var/lib/pm/index.json**: Runtime package index file maintained by `pm` inside the built image. Contains the final state of all installed OS packages after all pm commands execute. This is the single source of truth for os-pm SBOM data.
- **/var/lib/pm/container-factory-version**: File inside the built image containing the container factory version. Written during build from `PACKAGES_VERSION` if the variable is set. Read from the image during SBOM collection for the `containerFactoryVersion` PURL qualifier. If the file does not exist, the value SHALL be taken from the `PACKAGES_VERSION` environment variable directly.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: An `os-pm` directive with `spec: [curl==8.12.1, jq]` generates a single `pm install curl==8.12.1 jq` command (with env vars passed inline).
- **SC-002**: An `os-pm` directive with an empty `spec` list is rejected at config validation.
- **SC-003**: An `os-pm` directive with `workdir` specified is rejected at config validation.
- **SC-004**: Two `os-pm` sections in the same `packages` list generate two separate pm commands, both executed during the build.
- **SC-005**: The SBOM for os-pm is read from the mandatory `/var/lib/pm/index.json` inside the built image, not from any file in the build context; an absent index produces an error.
- **SC-006**: The SBOM contains all packages from both `os-pm` sections with correct names, versions, licenses, and dependencies.
- **SC-007**: The `containerFactoryVersion` PURL qualifier is sourced only from `/var/lib/pm/container-factory-version` in the image; version-read failures are observable in debug logs and no host environment fallback is used.
- **SC-008**: A build without any `os-pm` directive produces no pm commands and no os-pm SBOM components.
- **SC-009**: An `os-pm` directive using `spec: "pm.yaml"` (string path, the old file-based syntax) is rejected at config parse time.
- **SC-010**: All existing unit tests pass after the migration to inline syntax.
- **SC-011**: All e2e tests pass after the migration to inline syntax.
- **SC-012**: No os-pm package data is read from files in the build context (e.g., `pm.lock`); all os-pm SBOM data comes from the built image.
- **SC-013**: The `env` field continues to work with `os-pm` — environment variables are passed as inline prefixes to the `pm install` command.
- **SC-014**: A build with os-pm packages where the external refs server returns an error fails with an aggregated, hierarchical error listing failing image names and component details.

## Assumptions

- The `pm` binary is pre-installed in the builder image; werf does not install or manage it.
- The `pm` binary maintains `/var/lib/pm/index.json` automatically after package operations — werf reads this file, it does not write or modify it.
- The `pm install` command accepts multiple package arguments with version constraints (e.g., `pm install curl==8.12.1 jq`).
- Users who adopted the file-based syntax from 015 will need to update their `werf.yaml` configs to use inline `spec` list syntax — no automatic migration is provided.
- The `ContainerFactoryVersionFile` (`/var/lib/pm/container-factory-version`) is written during build by the generated command preamble and read during SBOM collection for PURL qualifier enrichment; read failures are debug-logged and are not replaced by a host environment fallback.
- The `managedinput` skip of os-pm (no syft cataloger derivation) is preserved — delivery-kit handles os-pm SBOM via its own code, not via syft catalogers.
- Existing `pm.yaml`/`pm.lock` files from the 015 approach in user projects become inert — werf ignores them.
- The `ParsePmInstalledJSON` function is reused to parse `/var/lib/pm/index.json` (same format as `pm.lock`).