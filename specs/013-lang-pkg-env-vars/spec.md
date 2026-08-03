# Feature Specification: lang-pkg-env-vars

**Feature Branch**: `013-lang-pkg-env-vars`

**Created**: 2026-08-03

**Status**: Draft

**Input**: User description: "поддержку переменных окружения для языковых менеджеров пакетов на основе specs/012-os-pm-env-vars"

## Clarifications

### Session 2026-08-03

- Q: Are the 5 listed language package types (`python-pip`, `npm`, `rust-cargo`, `go-mod`, `lua-rock`) the complete set of language package managers that should receive env var support? → A: No — the complete set found in the codebase at `pkg/config/packages_directive.go` is `go-mod`, `python-uv`, `python-pip`, `python-poetry`, `rust-cargo`, `javascript-npm`, `javascript-yarn`, `javascript-pnpm`, and `lua-rock`. The type name for npm is `javascript-npm`, not `npm`.

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

### User Story 1 - Install language packages from private registries (Priority: P1)

A user building a container image needs to install language packages (e.g., npm packages via `javascript-npm` or `javascript-yarn`, Python wheels via `python-pip` or `python-uv`, Rust crates via `rust-cargo`) from private registries that require authentication. The user sets registry-specific environment variables (e.g., `npm_config__authtoken`, `PIP_INDEX_URL`, `CARGO_REGISTRIES_MYREGISTRY_INDEX`) in the `packages[].env` section. These variables are passed to the underlying language package manager process, enabling authenticated package installation.

**Why this priority**: Authentication for private registries is the primary use case for env var support across all package managers. It directly enables enterprise use of language packages in CI/CD pipelines.

**Independent Test**: Can be tested by creating a build with a language package that depends on a private registry, setting the appropriate auth env vars in `packages[].env`, and verifying the package installs successfully.

**Acceptance Scenarios**:

1. **Given** a werf.yaml with a language package (e.g., `javascript-npm`) that depends on a private registry, **When** the user sets `npm_config__authtoken` in `packages[].env`, **Then** the package manager authenticates and installs packages from the private registry.
2. **Given** a werf.yaml with a language package and `packages[].env` containing auth-related variables, **When** the build runs, **Then** the environment variables are available to the underlying package manager process.

---

### User Story 2 - Customize language package manager behavior (Priority: P2)

A user needs to pass environment variables that influence language package manager behavior, such as `PIP_DISABLE_PIP_VERSION_CHECK=1`, `npm_config_cache=/path`, `GOPROXY=direct`, or `CARGO_NET_RETRY=3`.

**Why this priority**: Customization of package manager behavior is a common need for reproducible builds and CI/CD environments. A broad variety of package managers benefit from this.

**Independent Test**: Can be tested by setting a configuration env var in the language package's `env` section and verifying the package manager uses the expected configuration during installation.

**Acceptance Scenarios**:

1. **Given** a werf.yaml with a `python-pip` package, **When** the user sets `PIP_DISABLE_PIP_VERSION_CHECK=1` in `packages[].env`, **Then** pip suppresses its version check output.
2. **Given** a werf.yaml with a `rust-cargo` package, **When** the user sets `CARGO_NET_RETRY=3` in `packages[].env`, **Then** cargo retries failed downloads up to 3 times.

---

### User Story 3 - Proxy support for language package managers (Priority: P3)

A user building images inside a corporate network needs to install language packages through an HTTP/HTTPS proxy. They set proxy environment variables in the language package manager section.

**Why this priority**: Proxy support is a common enterprise requirement but is less critical than authentication and behavior customization.

**Independent Test**: Can be tested by configuring an intercepted proxy, setting `HTTP_PROXY` and `HTTPS_PROXY` env vars in the language package's `env` section, and verifying that package downloads go through the proxy.

**Acceptance Scenarios**:

1. **Given** a werf.yaml with a language package and `HTTP_PROXY` / `HTTPS_PROXY` set in `packages[].env`, **When** the build runs inside a proxied network, **Then** package downloads are routed through the specified proxy.

---

### Edge Cases

- What happens when `env` is specified for a language package type that does not support the particular variable? The variable is still passed to the package manager process; unsupported variables are silently ignored by the package manager itself.
- What happens when `env` contains duplicate keys at the YAML level? YAML parsers typically merge duplicate keys according to their merge strategy; the last value wins (standard YAML behavior).
- What happens when `env` contains an environment variable that shadows an existing system environment variable? The explicit value in `packages[].env` overrides the inherited value for the package manager process only.
- What happens when `env` is specified for a package type where no runtime implementation exists? The `env` field is parsed but silently ignored — no environment variables are passed. This is the current behavior for all language package types before this feature.
- What happens when multiple package manager contexts share the same env var name (e.g., `HTTP_PROXY` set for both `os-pm` and `javascript-npm`)? Each package type runs in a separate command invocation, so the env vars are scoped per package entry and cannot conflict.

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: The `packages[].env` field MUST be implemented at runtime for the following language package manager types: `go-mod`, `python-uv`, `python-pip`, `python-poetry`, `rust-cargo`, `javascript-npm`, `javascript-yarn`, `javascript-pnpm`, and `lua-rock`.
- **FR-002**: Environment variables defined in `packages[].env` MUST be passed to the child process running the underlying language package manager process, using the same inline environment variable prefix mechanism already established for `os-pm`.
- **FR-003**: The `env` field MUST NOT interfere with or override any top-level `imageSpec.config.env` — they serve different purposes (build-time tool env vs. runtime container env).
- **FR-004**: If `env` is omitted or empty, the language package manager MUST inherit the build process environment as before (backward compatible).
- **FR-005**: The build output MUST log the full key=value pairs of `packages[].env` for transparency, consistent with the behavior established for `os-pm`.
- **FR-006**: The system MUST validate environment variable names in `packages[].env` against POSIX naming rules (`[a-zA-Z_][a-zA-Z0-9_]*`) at config parse time for all package types, consistent with the validation already implemented for `os-pm`.

### Key Entities *(include if feature involves data)*

- **Package Config Entry**: A single entry in the `packages` array of type `go-mod`, `python-uv`, `python-pip`, `python-poetry`, `rust-cargo`, `javascript-npm`, `javascript-yarn`, `javascript-pnpm`, or `lua-rock`. Contains the package type, package specification (e.g., package names, lockfile path), and optionally an `env` map of environment variables.
- **Environment Variable**: A key-value pair where the key is a POSIX-valid variable name and the value is its string content. Set as an inline prefix before the package manager invocation command in the build script.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: Users can install language packages from private authenticated registries by setting auth-related environment variables in `packages[].env` for each supported language package type.
- **SC-002**: Backward compatibility is preserved — all existing werf.yaml files that use language packages without `env` continue to work without changes.
- **SC-003**: The feature works with all currently defined language package types: `python-pip`, `python-uv`, `python-poetry`, `go-mod`, `rust-cargo`, `javascript-npm`, `javascript-yarn`, `javascript-pnpm`, and `lua-rock`.
- **SC-004**: When `env` is specified for a language package, the package manager process receives those environment variables during execution. When `env` is omitted, the behavior is identical to before this feature.
- **SC-005**: Invalid env var names are rejected at config parse time for language package types, consistent with the behavior already established for `os-pm`.

## Assumptions

- The OS PM env vars feature (012-os-pm-env-vars) has already established the mechanism for passing environment variables to package manager subprocesses via inline shell prefix. This feature reuses the same mechanism for language package managers.
- Each language package manager type already has a working implementation for installing packages; this feature extends those implementations to pass user-defined environment variables to the package manager process.
- The `env` field is already accepted in the config schema for all package types per the OS PM env vars feature. No config schema changes are needed.
- Environment variable values are static strings defined at configuration time — dynamic or runtime-computed values are out of scope.