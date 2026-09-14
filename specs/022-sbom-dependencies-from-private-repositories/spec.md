# Feature Specification: SBOM Dependencies from Private Repositories

**Feature Branch**: `022-sbom-dependencies-from-private-repositories`

**Created**: 2026-09-09

**Status**: Draft

**Input**: User description: "Enable `sbom packages` to download dependencies from private GitLab Git repositories using configuration declared in `werf.yaml`."

## Project Context

**Delivery Kit** is a Go CLI tool for full-cycle CI/CD to Kubernetes. It is built on top of werf with Deckhouse Platform extensions. Key subsystems:

- **Build** (`pkg/build/`) — Container image building via Buildah
- **Deploy** (`pkg/deploy/`) — Kubernetes deployment via werf/nelm (Helm-based)
- **SBOM** (`pkg/sbom/`) — Software Bill of Materials generation and validation
- **Cleanup** (`pkg/cleaning/`) — Container registry cleanup policies
- **Signature** (`pkg/signature/`) — Container image signing and verification
- **Docker Registry** (`pkg/docker_registry/`) — OCI registry operations
- **Config** (`pkg/config/`) — werf.yaml configuration parsing

## Clarifications

### Session 2026-09-09

- Q: Should the configuration support multiple GitLab hosts simultaneously in a single `sbom packages` run? → A: Yes, multiple GitLab hosts must be supported automatically.
- Q: Should private GitLab access be enabled only when explicitly configured in `werf.yaml`, even if a `CI_JOB_TOKEN` secret is available in the environment? → A: Yes, use the token only when private GitLab access is explicitly configured in `werf.yaml`.
- Q: How should the command behave when dependencies reference multiple GitLab hosts in one run? → A: It must support multiple hosts automatically.
- Q: Should the same `CI_JOB_TOKEN` be used for all configured GitLab hosts in one run? → A: No, a separate token may be configured for each GitLab host.
- Q: How should a user associate a separate token with a specific GitLab host in `werf.yaml`? → A: Through a separately named secret explicitly associated with the corresponding host.
- Q: If a credential is missing or invalid for one configured GitLab host, should the entire run fail? → A: Yes, the entire run must fail; credential validation is delegated to the package manager at runtime, and werf must propagate that failure instead of producing a successful partial SBOM.
- Q: Should werf pre-validate whether a host-specific credential is present before starting the package manager? → A: No, werf performs no pre-validation; all credential and association errors are delegated to the package manager at runtime.
- Q: Should the package manager receive only credentials for GitLab hosts used by the current dependency graph, or all credentials declared in `werf.yaml`? → A: The package manager receives all credentials declared in `werf.yaml`; each credential remains applicable only to its explicitly associated GitLab host.
- Q: Should the command preserve the package manager's exit code and diagnostic message when private-repository access fails? → A: Yes, preserve both while adding safe werf context and excluding credentials from the output.
- Q: Should temporary authentication configuration be removed after package-manager completion both on success and on every error? → A: Yes, cleanup must run after successful retrieval and after every error, including runtime package-manager failures.

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Generate an SBOM from private GitLab dependencies (Priority: P1)

As a project maintainer, I want `sbom packages` to download dependencies from a private GitLab Git repository so that the generated SBOM represents the project’s complete dependency set rather than failing on inaccessible private packages.

**Why this priority**: Access to private dependencies is required for the primary workflow and is the reason this feature is requested.

**Independent Test**: Declare the private GitLab host, required ecosystem variables, and the `CI_JOB_TOKEN` secret in `werf.yaml`, then run `sbom packages` for a project whose dependencies include a private GitLab repository. The command completes and includes the accessible dependencies in the result.

**Acceptance Scenarios**:

1. **Given** a project declares the private GitLab host, required ecosystem-specific variables, and a valid `CI_JOB_TOKEN` secret in `werf.yaml`, **When** the project has a dependency hosted in that private GitLab repository and `sbom packages` runs, **Then** dependency retrieval succeeds and SBOM generation completes.
2. **Given** a project uses a private GitLab host other than the default public GitLab host, **When** its host is declared in `werf.yaml`, **Then** `sbom packages` uses the declared host without requiring a product-specific host allowlist.
3. **Given** a project uses any package ecosystem already supported by `sbom packages`, **When** its dependency mechanism retrieves a Git repository from a configured private GitLab host, **Then** the private-repository access behavior is available without requiring the workflow to be limited to Go modules.
4. **Given** a project has dependencies from multiple configured GitLab hosts and a separately named secret is associated with each host, **When** `sbom packages` runs, **Then** each dependency is retrieved using the credential associated with its host.

---

### User Story 2 - Preserve public dependency workflows (Priority: P2)

As a project maintainer, I want projects that use only public dependencies to continue working without adding private-repository configuration.

**Why this priority**: Existing users must not need to change working configurations when they do not need private access.

**Independent Test**: Run `sbom packages` for a project with public dependencies and no private-repository configuration, then verify that it completes with the same dependency coverage expected before this feature.

**Acceptance Scenarios**:

1. **Given** a project has only public dependencies and no private-repository settings, **When** `sbom packages` runs, **Then** it completes successfully without requiring `CI_JOB_TOKEN`.
2. **Given** a project has both public and private dependencies and declares valid private-repository settings, **When** `sbom packages` runs, **Then** public dependencies remain retrievable and private dependencies are retrieved through the configured access.

---

### User Story 3 - Fail safely when private access is unavailable (Priority: P1)

As a project maintainer, I want an actionable error when private dependency access cannot be authenticated, without exposing credentials.

**Why this priority**: A clear failure is safer and faster to diagnose than an opaque package-manager error or accidental credential disclosure.

**Independent Test**: Run `sbom packages` against a project requiring a private GitLab dependency with a missing or invalid token, and inspect the command result and generated outputs for a clear failure without the token value.

**Acceptance Scenarios**:

1. **Given** a private dependency is required and the credential configured for its GitLab host is missing, **When** the package manager attempts retrieval at runtime, **Then** the package-manager failure is propagated, the run fails, and the command does not print the token or secret contents.
2. **Given** a private dependency is required and the credential configured for its GitLab host is invalid or unauthorized, **When** the package manager attempts retrieval at runtime, **Then** the package-manager authentication failure is propagated, the run fails, and the command does not claim that the dependency was included.
3. **Given** one of several configured GitLab hosts cannot be accessed by its package manager, **When** `sbom packages` runs, **Then** the entire operation fails rather than producing a successful partial SBOM.
4. **Given** a private-repository run succeeds or fails, **When** the resulting image layers, logs, generated SBOMs, and build metadata are inspected, **Then** the token and temporary authentication configuration are absent.

### Edge Cases

- The configured GitLab hosts use self-managed domains rather than `gitlab.com`.
- Required ecosystem-specific variables are omitted while a private dependency is present.
- `CI_JOB_TOKEN` is declared but empty, malformed, expired, or lacks permission to read the repository.
- A project has no private dependencies but declares private-repository settings.
- A dependency URL uses a repository form that differs from the configured host’s canonical HTTPS form.
- A package manager emits an error containing a request URL; credentials must still not appear in user-visible output.
- A dependency graph mixes public repositories, private GitLab repositories, and inaccessible repositories.

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: The system MUST allow users to declare private GitLab repository access for `sbom packages` in `werf.yaml`.
- **FR-002**: The configuration MUST allow GitLab hosts to be selected by the user, MUST support self-managed GitLab hosts, and MUST support multiple GitLab hosts in one `sbom packages` run.
- **FR-003**: The configuration MUST allow users to explicitly pass the ecosystem-specific environment variables needed by their package manager into the `sbom packages` dependency-download context.
- **FR-004**: The system MUST accept a credential supplied through the existing werf secret mechanism for each configured GitLab host; the user MUST explicitly name and associate each host credential in `werf.yaml`, including any credential named `CI_JOB_TOKEN`.
- **FR-005**: When private-repository configuration and valid host-specific credentials are present, `sbom packages` MUST make all credentials declared in `werf.yaml` available only for the dependency-download operation and MUST allow supported package ecosystems to retrieve dependencies from private GitLab Git repositories.
- **FR-006**: The system MUST use `CI_JOB_TOKEN` for private-repository access only when private GitLab access is explicitly configured in `werf.yaml`; the mere presence of `CI_JOB_TOKEN` in the environment MUST NOT enable private-repository access.
- **FR-007**: When dependencies reference multiple GitLab hosts, the system MUST process the hosts automatically according to the declared private-repository configuration and MUST not fail solely because more than one GitLab host is present.
- **FR-008**: The system MUST allow each configured GitLab host to use its own credential and MUST apply that credential only to the corresponding host, even when credentials for other configured hosts are also available to the package manager.
- **FR-009**: The configuration MUST allow each host-specific credential to be explicitly associated with its GitLab host in `werf.yaml`; credentials MUST NOT be selected solely by discovery order or exposed as plaintext configuration values. Werf MUST NOT pre-validate whether the association or credential is present; such errors MUST be delegated to the package manager at runtime.
- **FR-010**: The private-repository behavior MUST apply to all package ecosystems already supported by `sbom packages` when their dependency mechanism retrieves dependencies from GitLab Git repositories; it MUST NOT be restricted to Go modules.
- **FR-011**: The system MUST remove or invalidate temporary private-repository authentication configuration after dependency retrieval, whether retrieval succeeds or fails, including runtime package-manager errors and interruptions.
- **FR-012**: The system MUST prevent the credential and temporary authentication configuration from appearing in image layers, command logs, generated SBOMs, and build metadata.
- **FR-013**: Projects that do not configure private-repository access MUST continue to retrieve public dependencies without requiring `CI_JOB_TOKEN`.
- **FR-014**: When private access is required but the credential is missing, empty, invalid, or unauthorized, the system MUST delegate the check to the package manager, propagate its runtime failure, fail the affected `sbom packages` operation, and preserve an actionable authentication-related error without exposing credentials.
- **FR-015**: When the package manager reports a private-repository access failure, the system MUST preserve its exit code and diagnostic message, add safe werf context, and redact credential values from the resulting output.
- **FR-016**: If dependency retrieval fails for any configured GitLab host, the system MUST fail the entire `sbom packages` operation and MUST NOT produce a successful partial SBOM.
- **FR-017**: The system MUST not report a private dependency as successfully included when its retrieval fails.
- **FR-018**: The generated dependency-download command and private-repository configuration MUST be unit-testable, including the presence of required configuration and the absence of exposed credential values.

### Key Entities

- **Private repository access configuration**: User-declared settings in `werf.yaml` that identify the GitLab hosts and ecosystem-specific variables needed to retrieve dependencies.
- **GitLab host credential**: A short-lived, explicitly named secret supplied and associated by the user in `werf.yaml` through the existing werf secret mechanism; `CI_JOB_TOKEN` is one possible user-selected secret name, not an implicit default.
- **Dependency-download context**: The bounded execution context in which package-manager operations can access explicitly declared variables and the host-specific credentials.
- **Generated SBOM**: The dependency inventory produced by `sbom packages`, which must contain dependency information but no credentials or temporary authentication data.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: For every package ecosystem supported by `sbom packages` that can retrieve dependencies from GitLab Git repositories, 100% of configured test cases with valid host-specific credentials complete dependency retrieval and SBOM generation successfully.
- **SC-002**: 100% of test cases using a user-declared self-managed GitLab host connect to the declared host rather than a fixed product-defined host.
- **SC-003**: 100% of public-only dependency runs without private-repository settings complete successfully without requiring `CI_JOB_TOKEN`.
- **SC-004**: 100% of missing, empty, invalid, and unauthorized-token scenarios delegated to package-manager runtime produce a propagated authentication-related failure, fail the overall operation, and do not report the inaccessible private dependency as included.
- **SC-005**: In 100% of successful and failed private-repository runs, credential values and temporary authentication configuration are absent from image layers, logs, generated SBOMs, and build metadata after cleanup executes.
- **SC-006**: Unit tests cover the generated dependency-download command and relevant configuration for private-repository access, including positive and negative credential-handling cases.

## Assumptions

- `sbom packages` already supports the package ecosystems included in this feature; the feature adds private GitLab Git access rather than adding new package managers.
- Users are responsible for declaring the environment variables required by their chosen ecosystem in `werf.yaml`; the feature does not infer a universal variable set.
- Each configured host credential has permission to read the private repositories assigned to that host when authentication is expected to succeed; credential names and host associations are selected explicitly by the user in `werf.yaml`.
- Private GitLab repositories are accessed through Git-compatible repository URLs; package registries that do not use Git repository retrieval are outside this feature’s scope.
- The existing werf secret mechanism remains the supported way to provide `CI_JOB_TOKEN` or other explicitly named host-specific credentials selected by the user in `werf.yaml`.
- Verification is limited to unit tests for generated dependency-download commands and private-repository configuration; full live private GitLab integration coverage is not required for this feature.
- No user-visible configuration is required for projects that only use public dependencies.
- Private-repository access is opt-in: an available `CI_JOB_TOKEN` does not activate the feature without explicit `werf.yaml` configuration.
- Multiple GitLab hosts may be handled in one `sbom packages` run when private-repository access is explicitly configured.
- A separate named secret may be assigned to each configured GitLab host, and credentials are not stored as plaintext configuration values.
