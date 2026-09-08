---
status: draft
feature: alternative-language-package-managers
created: 2026-09-07
source: user description and Kaiten card 69642569
---

# Alternative Language Package Managers for Packages Directive

## Clarifications

### Session 2026-09-07

- Q: Should the alternative-manager version field accept only an exact version or also version ranges? → A: Only an exact version, such as `2.4.3`.
- Q: What should happen if an exact alternative-manager version is not specified? → A: The configuration without an exact version must be rejected.
- Q: If the alternative manager is already installed in the builder image, should the build use it only when its version exactly matches the version in `werf.yaml`? → A: At this stage, the selected alternative manager must not be present in the builder image; pre-installed alternative-manager reuse and version checking are out of scope.
- Q: If dependency installation fails after the alternative manager has been installed successfully, must the system remove that manager before returning the error? → A: Cleanup runs only after dependency installation succeeds.
- Q: Should e2e tests cover every alternative manager — Yarn, pnpm, uv, and Poetry — or is one manager per ecosystem sufficient? → A: Each manager requires a separate e2e test.

## User Scenarios & Testing

### User Story 1 - Install JavaScript dependencies with an unavailable alternative manager (Priority: P1)

A user builds a JavaScript or TypeScript project whose dependencies are managed by Yarn or pnpm, while the builder image provides npm but does not provide the selected alternative manager. The user declares the corresponding package type in `werf.yaml` and does not need to modify the builder image just to add that manager.

**Why this priority**: This removes the current requirement to maintain custom builder images for common JavaScript package managers and enables SBOM generation for those projects.

**Independent Test**: Build a project with a lock file and a package type for Yarn or pnpm in a builder image containing npm but not the selected alternative manager; verify that dependencies are installed and the resulting image does not retain the alternative manager.

**Acceptance Scenarios**:

1. **Given** a JavaScript/TypeScript project with the appropriate manifest and lock file, **when** the user selects an alternative JavaScript package type, **then** the primary JavaScript package manager installs that alternative manager, the alternative manager installs the project dependencies, and the alternative manager is removed before the build stage finishes.
2. **Given** a project with an alternative manager version specified in `werf.yaml`, **when** the build runs, **then** the requested version is used for dependency installation.
3. **Given** a project with an alternative manager that is not present in the builder image, **when** the build runs, **then** the build does not fail solely because the alternative manager was initially absent.

---

### User Story 2 - Install Python dependencies with an unavailable alternative manager (Priority: P1)

A user builds a Python project whose dependencies are managed by uv or Poetry, while the builder image provides pip but does not provide the selected alternative manager. The user declares the corresponding package type in `werf.yaml` and relies on pip to bootstrap the manager only for the dependency installation step.

**Why this priority**: Python projects using uv or Poetry currently require those tools to be baked into the builder image, which prevents reuse of standard images and adds maintenance overhead.

**Independent Test**: Build a project with a lock file and a Python alternative package type in a builder image containing pip but not the selected alternative manager; verify that dependencies are installed and the resulting image does not retain the alternative manager.

**Acceptance Scenarios**:

1. **Given** a Python project with the appropriate manifest and lock file, **when** the user selects uv or Poetry, **then** pip installs that manager, the selected manager installs the project dependencies, and the selected manager is removed before the build stage finishes.
2. **Given** a project with an alternative manager version specified in `werf.yaml`, **when** the build runs, **then** the requested version is used for dependency installation.
3. **Given** a project using the primary Python package type, **when** the build runs, **then** pip continues to install dependencies without adding an alternative-manager bootstrap or cleanup step.

---

### User Story 3 - Preserve deterministic dependency installation and SBOM coverage (Priority: P1)

A user expects the same lock-file validation and package inventory when the alternative package manager is used for the current build. The selected alternative manager is absent from the builder image, is installed into an ephemeral scope, and is removed after successful dependency installation without changing shared builder state.

**Why this priority**: Ephemeral installation must not weaken reproducibility or cause the SBOM to omit dependencies installed by the alternative manager.

**Independent Test**: Run successful and failing builds for each supported alternative manager with valid and invalid lock files; verify deterministic failure behavior, dependency installation, cleanup, and SBOM contents.

**Acceptance Scenarios**:

1. **Given** a valid project lock file, **when** an alternative manager installs dependencies, **then** the build uses the manager's locked/declarative installation behavior and the SBOM contains the installed project dependencies.
2. **Given** a missing or inconsistent lock file where the selected manager requires a valid lock file, **when** the build runs, **then** the build fails and reports the dependency installation failure.
3. **Given** that dependency installation fails after the alternative manager was bootstrapped, **when** the build terminates, **then** the build reports the original dependency installation error and does not run the successful-installation cleanup step, so the temporary manager may remain available in the failed intermediate state for diagnosis.

---

### Edge Cases

- The requested alternative manager version does not exist or cannot be downloaded; the build fails with an actionable error and does not continue to dependency installation.
- The user specifies an empty, malformed, or otherwise invalid manager version; configuration validation rejects it before starting the build.
- The primary manager required for bootstrapping is absent from the builder image; the build fails and identifies the missing prerequisite.
- The selected alternative manager is already present in the builder image; the build fails because pre-installed alternative-manager reuse is out of scope for this version of the feature.
- A project contains multiple package directives for different work directories; each directive bootstraps, uses, and cleans up its selected alternative manager without changing the behavior of unrelated directives.
- The primary package type is selected for JavaScript/TypeScript or Python; no temporary alternative manager is installed.
- Cleanup must not remove files or tools that were present in the builder image before the directive ran.
- A dependency installation command fails; the failure is preserved rather than hidden by cleanup, and cleanup is not required for the failed operation.

## Requirements

### Functional Requirements

- **FR-001**: The packages feature MUST support ephemeral alternative-manager installation for the currently supported non-primary JavaScript/TypeScript package types: `javascript-yarn` and `javascript-pnpm`.
- **FR-002**: The packages feature MUST support ephemeral alternative-manager installation for the currently supported non-primary Python package types: `python-uv` and `python-poetry`.
- **FR-003**: For JavaScript/TypeScript alternative package types, npm MUST be used as the primary manager to install the selected alternative manager before dependency installation.
- **FR-004**: For Python alternative package types, pip MUST be used as the primary manager to install the selected alternative manager before dependency installation.
- **FR-005**: The selected alternative manager MUST be made available for dependency installation by installing it into an ephemeral scope because it is not permitted to be present in the builder image at the beginning of the operation.
- **FR-006**: The selected alternative manager MUST be removed after it has successfully installed the project dependencies and before the successful build stage completes.
- **FR-007**: Cleanup MUST remove the alternative-manager installation created for the current operation, and the build MUST reject a builder image that already contains the selected alternative manager.
- **FR-008**: Each alternative package type MUST retain its existing manifest, lock-file, dependency-installation, and SBOM behavior except for the additional bootstrap and cleanup lifecycle.
- **FR-009**: Users MUST specify an exact alternative-manager version for every supported alternative package directive; omitting the version MUST be rejected during configuration validation.
- **FR-010**: Users MUST be able to specify an alternative manager version for each supported alternative package directive through `werf.yaml`.
- **FR-011**: A specified version MUST be an exact version, such as `2.4.3`, MUST constrain the ephemeral manager installation to that exact version, and MUST be applied independently for each package directive.
- **FR-012**: Missing, non-exact, malformed, or otherwise invalid alternative-manager version values MUST be rejected during configuration validation before project dependencies are installed.
- **FR-013**: The primary package types `javascript-npm` and `python-pip` MUST retain their current behavior and MUST NOT bootstrap or remove an alternative manager.
- **FR-014**: The build MUST fail when bootstrap, dependency installation, or lock-file validation cannot complete successfully, and the original failure MUST remain diagnosable; cleanup is required only after successful dependency installation, and a cleanup failure MUST fail the build.
- **FR-015**: The SBOM MUST continue to include dependencies installed through an ephemeral alternative manager and MUST associate them with the declared project files and lock files.
- **FR-016**: The feature MUST support multiple package directives in one image without sharing version or cleanup state between directives.
- **FR-017**: The feature MUST be limited to the JavaScript/TypeScript and Python package types listed in this specification; package types from other ecosystems are not changed by this feature.
- **FR-018**: End-to-end tests MUST include a separate scenario for each supported alternative manager — Yarn, pnpm, uv, and Poetry — using builder images that provide the corresponding primary manager and do not contain the selected alternative manager. Each scenario MUST verify that a pre-installed selected alternative manager is rejected if that condition can be represented by the fixture.

### Key Entities

- **Package directive**: A user-declared dependency installation entry containing the ecosystem type, working directory, project files, and the required exact alternative-manager version for non-primary package types.
- **Primary package manager**: The manager already expected from the builder image and authorized to install an alternative manager: npm for JavaScript/TypeScript and pip for Python.
- **Alternative package manager**: Yarn, pnpm, uv, or Poetry, installed only for the current dependency installation operation.
- **Manager version**: The required exact user-provided version identifying the alternative-manager version to bootstrap.
- **Dependency installation scope**: The operation bounded by bootstrap, project dependency installation, SBOM-visible dependency state, and cleanup.

## Success Criteria

### Measurable Outcomes

- **SC-001**: Projects using each supported alternative package type complete dependency installation successfully in a builder image that contains the corresponding primary manager but not the alternative manager.
- **SC-002**: In 100% of successful builds, the temporary manager scope is absent from the resulting image; a builder image containing the selected alternative manager is rejected, and cleanup is not required for failed builds.
- **SC-003**: In 100% of successful builds with a valid specified manager version, dependency installation uses that exact requested version from the ephemeral installation.
- **SC-004**: In 100% of builds with a missing or inconsistent required lock file, the build fails rather than completing with an unvalidated dependency set.
- **SC-005**: SBOM output for each supported alternative package type contains the project dependencies represented by its manifest and lock file, with no loss caused by temporary manager installation or removal.
- **SC-006**: Existing projects using `javascript-npm` or `python-pip` produce the same dependency installation outcome as before the feature is enabled and do not incur alternative-manager lifecycle steps.
- **SC-007**: A user can enable an alternative manager without changing the builder image, provided the corresponding primary manager and network/package source access are available.
- **SC-008**: Error output identifies whether bootstrap, dependency installation, version resolution, lock validation, cleanup, or a forbidden pre-installed alternative manager caused failure in all tested failure scenarios.
- **SC-009**: Four dedicated e2e scenarios — Yarn, pnpm, uv, and Poetry — pass with coverage for missing-manager isolation, verifying successful dependency installation, SBOM generation, rejection of pre-installed selected managers, and removal of temporary manager scopes; the Poetry fixture uses a builder image with pip as one representative Python case.

## Assumptions

- The builder image contains npm for JavaScript/TypeScript directives and pip for Python directives, unless the user chooses a custom image that provides equivalent primary-manager capabilities.
- The builder has access to the package source required to bootstrap the alternative manager and install project dependencies.
- Existing supported package types and their lock-file semantics remain authoritative; this feature does not introduce new lock-file formats or alter SBOM cataloger definitions.
- Builder images used with alternative package directives do not contain the selected alternative manager; pre-installed alternative-manager reuse is out of scope for this feature version.
- Every supported alternative package directive includes an exact manager version; configurations that omit it are invalid.
- Cleanup is part of the successful dependency installation lifecycle and is evaluated before the build stage is considered successful; failed builds may retain temporary state for diagnosis.
- Bun, Deno, and package managers not represented by the supported package directive types are out of scope.
- The exact YAML field name for the required version is defined during planning and implementation, but the field is scoped to an individual package directive and accepts an exact package-manager version, not a version range.
