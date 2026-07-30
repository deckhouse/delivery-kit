# Feature Specification: os-pm-env-vars

**Feature Branch**: `012-os-pm-env-vars`

**Created**: 2026-07-30

**Status**: Draft

**Input**: User description: "поддержку переменных окружения для pm"

## Project Context

**Delivery Kit** is a Go CLI tool for full-cycle CI/CD to Kubernetes. It is built on top of werf with Deckhouse Platform extensions. Key subsystems:

- **Build** (`pkg/build/`) — Container image building via Buildah
- **Deploy** (`pkg/deploy/`) — Kubernetes deployment via werf/nelm (Helm-based)
- **SBOM** (`pkg/sbom/`) — Software Bill of Materials generation and validation
- **Cleanup** (`pkg/cleaning/`) — Container registry cleanup policies
- **Signature** (`pkg/signature/`) — Container image signing and verification
- **Docker Registry** (`pkg/docker_registry/`) — OCI registry operations
- **Config** (`pkg/config/`) — werf.yaml configuration parsing

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Install packages from private registry using Docker config secret (Priority: P1)

A user building a container image needs to install OS packages from a private registry. The registry credentials are stored in a Docker config file mounted into the build container via the `secrets` directive. The user sets `DOCKER_CONFIG` environment variable for the os-pm package manager to point to the secrets mount point, so that package installation can authenticate against the private registry.

**Why this priority**: This is the primary use case — enabling authentication for private package registries. It unlocks the core value of the env support feature.

**Independent Test**: Can be tested by creating a build with a private registry package, mounting a Docker config secret, setting `DOCKER_CONFIG` env var in the os-pm section, and verifying the package installs successfully.

**Acceptance Scenarios**:

1. **Given** a werf.yaml with packages that depend on a private registry, **When** the user sets `DOCKER_CONFIG: /run/secrets/` in the `packages[].env` section and mounts a valid Docker config via `secrets`, **Then** the package manager authenticates and installs packages from the private registry.
2. **Given** a werf.yaml with `packages[].env` containing `DOCKER_CONFIG`, **When** the build runs, **Then** the environment variable is available to the underlying package manager process.

---

### User Story 2 - Install packages through a corporate proxy (Priority: P2)

A user building images inside a corporate network needs to install packages through an HTTP/HTTPS proxy. They set proxy environment variables in the os-pm package manager section.

**Why this priority**: Proxy support is a common enterprise requirement and a natural extension of the env support feature.

**Independent Test**: Can be tested by configuring an intercepted proxy, setting `HTTP_PROXY` and `HTTPS_PROXY` env vars in the os-pm section, and verifying that package downloads go through the proxy.

**Acceptance Scenarios**:

1. **Given** a werf.yaml with packages and `HTTP_PROXY` / `HTTPS_PROXY` set in `packages[].env`, **When** the build runs inside a proxied network, **Then** package downloads are routed through the specified proxy.
2. **Given** a werf.yaml with `packages[].env` containing proxy variables, **When** the build runs without proxy access, **Then** package installation fails with a meaningful error message indicating network/proxy failure.

---

### User Story 3 - Customize package manager behavior (Priority: P3)

A user needs to pass environment variables that influence package manager behavior, such as `DEBIAN_FRONTEND=noninteractive` for apt or custom repository URLs.

**Why this priority**: This is a convenience use case that extends the flexibility of the os-pm package manager but is not critical for the initial implementation.

**Independent Test**: Can be tested by setting `DEBIAN_FRONTEND=noninteractive` in the os-pm env section and verifying that apt does not prompt for interactive input during installation.

**Acceptance Scenarios**:

1. **Given** a werf.yaml with `DEBIAN_FRONTEND=noninteractive` set in `packages[].env`, **When** a package install triggers interactive prompts, **Then** apt uses the non-interactive frontend automatically.

---

### Edge Cases

- What happens when `env` is specified but empty? The system should treat it as if `env` was not specified — normal behavior with no additional environment variables.
- What happens when `env` contains a variable with an empty string value (`SOME_VAR: ""`)? The system must pass the empty value as-is to the package manager process, matching POSIX semantics (variable is set but empty).
- What happens when `env` contains an invalid variable name (empty key, starts with a digit, or contains special characters like `=`)? The system MUST reject the configuration at parse time with a clear error message describing the invalid name and the expected POSIX pattern.
- What happens when `env` contains an environment variable that shadows an existing system environment variable? The explicit value in `packages[].env` MUST override the inherited value for the package manager process only.
- What happens when secrets are referenced by `env` values pointing to non-existent files? The system should pass the env as-is; any resulting error from the package manager process is surfaced in the build output.
- What happens when `env` is specified for a non-`os-pm` package type? The `env` field is parsed but silently ignored — no environment variables are passed. Implementations for other package types can be added in future features.

## Clarifications

### Session 2026-07-30

- Q: Should environment variable values set via `packages[].env` be masked/hidden in build logs? → A: No masking — log full key=value pairs (simplest approach, responsibility for secrets is on the user).
- Q: Should the system validate environment variable names against POSIX naming rules and reject invalid names at config parse time? → A: Yes — validate against POSIX rules (`[a-zA-Z_][a-zA-Z0-9_]*`) and reject with a clear error at config parse time.
- Q: Should empty string values be allowed in `packages[].env`? → A: Yes — allow empty values (matches POSIX semantics, less restrictive).
- Q: Should the `env` field be supported for all package types or remain exclusive to `os-pm`? → A: Make `env` available to all package types in the config schema, but only implement the runtime behavior for `os-pm` initially.

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: The `packages` configuration MUST support an optional `env` field as a mapping of string key-value pairs.
- **FR-002**: The `env` field MUST be accepted in the config schema for all package types, but the runtime behavior (passing the variables to the underlying package manager process) MUST be implemented only for the `os-pm` type initially. For other package types, the `env` field MUST be parsed but silently ignored.
- **FR-003**: Environment variables defined in `packages[].env` MUST be passed to the child process running the underlying package manager (apt, apk, yum, etc.).
- **FR-004**: The `env` field MUST NOT interfere with or override any top-level `imageSpec.config.env` — they serve different purposes (build-time tool env vs. runtime container env).
- **FR-005**: If `env` is omitted or empty, the package manager MUST inherit the build process environment as before (backward compatible).
- **FR-006**: Values in `env` MAY reference paths mounted via the `secrets` directive.
- **FR-007**: The system MUST validate that `env` is a mapping of strings to strings at config parse time. Invalid types (numbers, booleans, nested structures) MUST produce a clear configuration parse error.
- **FR-008**: The build output MUST log the full key=value pairs of `packages[].env` for transparency. Users are responsible for not placing secrets directly in env var values.
- **FR-009**: The system MUST validate environment variable names in `packages[].env` against POSIX naming rules (`[a-zA-Z_][a-zA-Z0-9_]*`) at config parse time. Invalid names (empty keys, names starting with a digit, names containing `=` or other special characters) MUST produce a clear configuration parse error.

### Key Entities *(include if feature involves data)*

- **Package Config Entry**: A single entry in the `packages` array. Contains `type`, `spec`, and optionally `env`. The `env` is a map of `string → string` representing environment variables to set for the package manager process.
- **Environment Variable**: A key-value pair where the key is a variable name and the value is its string content. Set in the process environment of the package manager invocation.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: Users can install packages from private authenticated registries by setting `DOCKER_CONFIG` in `packages[].env` and mounting a Docker config via `secrets`.
- **SC-002**: Backward compatibility is preserved — all existing werf.yaml files that use `os-pm` without `env` continue to work without changes.
- **SC-003**: Invalid `env` values (non-string types) produce a clear error during configuration parsing, before any build steps execute.
- **SC-004**: The feature works with at least the following package manager families: apt (Debian/Ubuntu), apk (Alpine), and yum (RHEL/CentOS).

## Assumptions

- The `env` field is accepted in the config schema for all package types, but runtime behavior is only implemented for `os-pm`. Other package types silently ignore the field.
- Environment variable values are static strings defined at configuration time — dynamic or runtime-computed values are out of scope.
- The underlying build system (Buildah/Docker) already has the capability to pass environment variables to child processes; this feature only needs to wire the config value through.
- The `secrets` mechanism already exists and is capable of mounting files into the build container; this feature does not need to introduce new secret handling.