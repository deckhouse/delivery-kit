# Feature Specification: multiple os-pm sections

**Feature Branch**: `018-multiple-os-pm-sections`

**Created**: 2026-08-17

**Status**: Draft

**Input**: User description: "необходимо убедиться, что несколько секций os-pm в yaml файле работают"

## Project Context

**Delivery Kit** is a Go CLI tool for full-cycle CI/CD to Kubernetes. It is built on top of werf with Deckhouse Platform extensions. Key subsystems:

- **Build** (`pkg/build/`) — Container image building
- **Config** (`pkg/config/`) — YAML configuration parsing and validation
- **SBOM** (`pkg/sbom/`) — Software Bill of Materials generation and validation

The `os-pm` package directive installs operating-system packages during an image build. A single `packages` list may contain multiple `os-pm` entries, each with its own package specification and optional environment variables.

## Clarifications

### Session 2026-08-17

- Q: If one `os-pm` section fails, should subsequent sections stop executing? → A: Stop subsequent sections immediately after the first failure; the build fails.
- Q: Should the execution order of `os-pm` sections be preserved relative to all other `packages` sections? → A: Yes, all `packages` sections execute in their complete YAML order.
- Q: If two sections install the same package, how should a duplicate be identified in the final SBOM? → A: This is not validated within this specification; duplicate and version rules are defined by `pm`.
- Q: What does delivery-kit validate in an `os-pm` `spec`? → A: Only whether the `spec` is present and contains records; each record's content is passed to `pm` without interpretation by delivery-kit.
- Q: What restrictions apply to `packages[].env` for `os-pm` sections? → A: `PM_LOCK_FILE` is forbidden in every `os-pm` section, whether the configuration contains one section or multiple sections; when multiple sections are present, `PACKAGES_VERSION` must either be defined in every section with the same value or omitted from every section. This keeps the `pm` index version uniform and the build deterministic.

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Install packages from multiple os-pm sections (Priority: P1)

As an image author, I want to declare more than one `os-pm` section in the same YAML file so that packages can be installed in separate steps while remaining part of the same image build.

Example:

```yaml
packages:
  - type: os-pm
    spec:
      - curl
      - jq
  - type: os-pm
    spec:
      - ca-certificates
```

**Why this priority**: Supporting multiple sections is the core requested behavior and prevents valid package declarations from being dropped, overwritten, or merged incorrectly.

**Independent Test**: Build an image from a YAML file containing two non-empty `os-pm` sections and verify that both sections install their declared packages.

**Acceptance Scenarios**:

1. **Given** a valid YAML file with two `os-pm` sections, **When** the image is built, **Then** both sections are accepted and processed.
2. **Given** two `os-pm` sections with different package lists, **When** the build runs, **Then** one package-manager invocation is generated for each section and each invocation contains only that section's packages.
3. **Given** three `os-pm` sections, **When** the build runs, **Then** all three sections are processed in their YAML order without any section being skipped or replacing another.
4. **Given** `packages` entries of several supported types interleaved with multiple `os-pm` sections, **When** the build runs, **Then** all entries are processed in their complete YAML order.

---

### User Story 2 - Preserve per-section configuration (Priority: P1)

As an image author, I want each `os-pm` section to retain its own environment settings so that separate package installations can use different registries, proxies, or package-manager options.

**Why this priority**: Independent section configuration is necessary for multiple sections to be useful; applying one section's settings to another can cause incorrect installations or credential leakage.

**Independent Test**: Build with two sections that use distinct environment values and verify each package-manager invocation receives only its own values.

**Acceptance Scenarios**:

1. **Given** two `os-pm` sections with different `env` mappings, **When** the build runs, **Then** each generated invocation uses the environment mapping from its corresponding section.
2. **Given** one `os-pm` section with `env` and one without `env`, **When** the build runs, **Then** the first invocation receives its configured variables and the second retains normal inherited behavior.
3. **Given** any `os-pm` section sets `PM_LOCK_FILE` in `env`, **When** the configuration is validated, **Then** validation fails because delivery-kit must derive package state from the current image rather than a user-selected lock file.
4. **Given** multiple `os-pm` sections, **When** `PACKAGES_VERSION` is set in every section with the same value, **Then** configuration validation succeeds because all sections use the same `pm` index version and the build remains deterministic.
5. **Given** multiple `os-pm` sections, **When** `PACKAGES_VERSION` is set in only some sections or has different values, **Then** configuration validation fails because the sections could use different `pm` index versions; the error requires the variable to be set consistently in every section or removed from every section.
6. **Given** multiple sections in a valid YAML file, **When** one section fails to install its packages, **Then** the build reports the failure, stops processing subsequent sections, and does not falsely report the entire set as successfully installed.

---

### User Story 3 - Produce a complete final SBOM (Priority: P1)

As an image author, I want the resulting software inventory to include packages installed by every `os-pm` section so that the image's SBOM reflects its final state.

**Why this priority**: A successful build with an incomplete inventory is unsafe for audit, vulnerability assessment, and release decisions.

**Independent Test**: Build an image with multiple sections installing distinct packages and verify the final SBOM contains the installed packages from all sections.

**Acceptance Scenarios**:

1. **Given** multiple successful `os-pm` sections, **When** SBOM generation runs, **Then** the final SBOM contains the packages installed by every section.
2. **Given** multiple sections that install overlapping packages, **When** SBOM generation runs, **Then** the final SBOM reflects the package state reported by `pm`; duplicate and version-conflict validation is not performed by this feature.
3. **Given** a build with no `os-pm` sections, **When** SBOM generation runs, **Then** no package-manager commands or `os-pm` components are produced.

### Edge Cases

- A YAML file with an empty `os-pm` section is rejected during configuration validation, and other sections are not silently used as a substitute.
- A YAML file with an `os-pm` section whose `spec` is absent or contains no records is rejected with a configuration error.
- Package names, versions, and package-manager syntax inside `spec` records are not interpreted or validated by delivery-kit; `pm` handles their validation.
- `PM_LOCK_FILE` is rejected in the `env` mapping of every `os-pm` section, including configurations with only one `os-pm` section.
- When multiple `os-pm` sections are present, a configuration that sets `PACKAGES_VERSION` in only some sections or uses different values is rejected because it cannot guarantee one `pm` index version and deterministic package resolution; the variable must be set in every section with the same value or omitted from every section.
- A YAML file with one invalid section among valid sections fails validation before a partial build is presented as successful.
- If a package-manager invocation fails, no subsequent `os-pm` section is executed.
- The order of non-`os-pm` package sections relative to multiple `os-pm` sections does not cause any valid `os-pm` section to be lost or duplicated.
- An `os-pm` section with a per-section environment variable that has an empty value preserves that value for that invocation.
- If the final package index required for SBOM generation is absent, the behavior follows the established os-pm contract: no os-pm components are emitted when no package state exists; malformed package-index data produces a descriptive failure.

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: The YAML configuration MUST allow one or more `os-pm` entries in the `packages` list.
- **FR-002**: Each `os-pm` entry MUST be represented as an independent configuration item with its own `spec` and optional `env` values.
- **FR-003**: The system MUST preserve the complete YAML order of all `packages` entries when generating and executing package operations, including the relative position of `os-pm` entries and entries of other supported types.
- **FR-004**: The system MUST generate exactly one package-manager invocation for each valid `os-pm` entry, with that entry's package list and no packages from another entry.
- **FR-005**: The system MUST apply each entry's `env` mapping only to the corresponding package-manager invocation. An omitted or empty mapping MUST preserve inherited behavior.
- **FR-006**: The system MUST reject `PM_LOCK_FILE` in the `env` mapping of every `os-pm` entry before starting an image build, whether the configuration contains one entry or multiple entries, because using a user-selected lock file could make the package state read by delivery-kit stale.
- **FR-007**: When multiple `os-pm` entries are present, the system MUST require `PACKAGES_VERSION` to be either present in every entry with identical values or absent from every entry. Because the variable selects the `pm` index version, a configuration where only some entries define it or where values differ MUST be rejected before the image build starts to preserve deterministic package resolution.
- **FR-008**: The system MUST validate every `os-pm` entry before starting an image build by checking that its `spec` is present and contains at least one record.
- **FR-009**: Delivery-kit MUST pass each non-empty `spec` record to `pm` without interpreting or validating package names, versions, duplicate declarations, or package-manager syntax.
- **FR-010**: If an `os-pm` entry has no `spec` or an empty `spec`, the system MUST return a configuration error before any build step starts. The system MUST NOT report a partially processed configuration as successful.
- **FR-011**: If any package-manager invocation fails, the build MUST fail, identify the failed operation sufficiently for the user to diagnose the corresponding section, and stop before executing subsequent `os-pm` sections.
- **FR-012**: The system MUST recognize whether any `os-pm` entries are present without relying on a single stored section or a single manifest path, so that multiple entries remain discoverable.
- **FR-013**: After all successful package-manager invocations, the SBOM MUST represent the final installed package state and include packages contributed by every successfully processed `os-pm` section.
- **FR-014**: Package names, versions, duplicate declarations, and package-manager syntax MUST be validated and resolved by `pm`; delivery-kit MUST NOT add independent validation rules for them.
- **FR-015**: A configuration without `os-pm` entries MUST remain supported and MUST not trigger os-pm processing.
- **FR-016**: Existing single-section inline `os-pm` configurations MUST retain their current behavior.
- **FR-017**: Existing per-section environment-variable behavior for `os-pm` MUST remain available when multiple sections are used.

### Key Entities

- **Packages list**: Ordered collection of package entries declared for an image build.
- **os-pm section**: One package entry with a non-empty inline package specification and optional environment mapping.
- **Package-manager invocation**: One execution derived from exactly one `os-pm` section.
- **Final package state**: The package inventory after all successful invocations have completed; it is the source used to form the os-pm portion of the SBOM.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: A YAML file containing two valid `os-pm` sections completes configuration validation without losing either section.
- **SC-002**: A build with N valid `os-pm` sections generates and executes N package-manager invocations in YAML order for every tested N from 2 through 5, while preserving their position relative to interleaved supported package types.
- **SC-003**: In a two-section test with distinct package lists, 100% of packages from both sections are present in the final installed state and no package from either section is omitted.
- **SC-004**: In a two-section test with distinct environment mappings, each invocation receives its matching mapping and receives no value belonging only to the other section.
- **SC-005**: A configuration containing `PM_LOCK_FILE` in any `os-pm` environment mapping is rejected before any image build step begins in 100% of validation tests.
- **SC-006**: For multiple `os-pm` sections, configurations that define `PACKAGES_VERSION` in every section with the same value, or omit it from every section, are accepted; configurations that define it in only some sections or with different values are rejected before any image build step begins in 100% of validation tests, ensuring one `pm` index version and deterministic package resolution.
- **SC-007**: An `os-pm` entry with an absent or empty `spec` is rejected before any image build step begins in 100% of validation tests; non-empty records are passed through without content validation by delivery-kit.
- **SC-008**: A failed package-manager invocation causes the build to fail in 100% of failure tests, prevents every subsequent section from executing, and never produces a success result for the complete image.
- **SC-009**: The final SBOM reflects the package state reported by `pm`; package names, versions, duplicate declarations, and package-manager syntax are not independently validated by delivery-kit.
- **SC-010**: Existing single-section and no-section configurations continue to pass their existing validation and behavior tests.

## Assumptions

- The supported inline `os-pm` syntax is a `spec` list of package-name strings; file-based manifests are outside this feature's scope.
- The package manager and its runtime package index are already available through the existing build environment.
- The established mechanism for reading the final package state and producing the os-pm SBOM is reused; this feature does not introduce a new SBOM format.
- Package installation remains sequential and follows declaration order; parallel installation is not required.
- Package names, versions, duplicate declarations, and package-manager syntax are validated by `pm`, not by delivery-kit.
- Existing validation rules for environment-variable names, secrets, and supported package-manager families remain unchanged.
- `PM_LOCK_FILE` is reserved by delivery-kit and cannot be supplied through any `os-pm` section's `env` mapping, regardless of how many `os-pm` sections the configuration contains.
- When several `os-pm` sections are present, `PACKAGES_VERSION` is a shared build-level setting that selects the `pm` index version: it must be identical in every section or omitted from every section so package resolution remains deterministic.
- No automatic migration of user configuration is required.
