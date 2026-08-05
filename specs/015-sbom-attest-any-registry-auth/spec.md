# Feature Specification: Default Registry Auth for OCI Artifact Attestation Retrieval

**Feature Branch**: `fix/sbom/attest-any-registry-auth`

**Created**: 2026-08-05

**Status**: migrated

**Input**: Reverse-engineered from source code changes in branch `fix/sbom/attest-any-registry-auth` (1 commit on top of `origin/main`)

## Project Context

**Delivery Kit** is a Go CLI tool for full-cycle CI/CD to Kubernetes. It is built on top of werf with Deckhouse Platform extensions. Key subsystems:

- **Build** (`pkg/build/`) — Container image building via Buildah
- **Deploy** (`pkg/deploy/`) — Kubernetes deployment via werf/nelm (Helm-based)
- **SBOM** (`pkg/sbom/`) — Software Bill of Materials generation and validation
- **Cleanup** (`pkg/cleaning/`) — Container registry cleanup policies
- **Attestation** (`pkg/attestation/`) — In-toto attestation signing, verification, retrieval, and listing
- **OCI Artifact** (`pkg/oci/artifact/`) — OCI artifact attachment and fallback index management
- **Docker Registry** (`pkg/docker_registry/`) — OCI registry operations
- **Config** (`pkg/config/`) — werf.yaml configuration parsing

The OCI artifact package provides a `Store` interface for attaching and retrieving OCI artifacts (SBOMs, attestations) to container images stored in a registry. Authentication with the container registry is handled either through explicit `remote.Option` parameters passed at construction time, or through the global `docker_registry` API for default auth (Docker config, EC2 ECR, etc.).

The `OCIStore` struct uses a helper method `remoteOptions(ctx)` that returns explicit options if provided, or falls back to `docker_registry.API().RemoteOptionsForHost(ctx, repo)` if no explicit options are set.

## User Scenarios & Testing *(mandatory)*

### User Story 1 — Retrieve attestation content from any authenticated registry (Priority: P1)

A user or internal subsystem (SBOM merge, attestation get) needs to pull the content of an artifact attached to an image stored in a private registry. The `GetAttachedContentAny` method is called without an `imageName` to find the first artifact of a given type. It must authenticate using the configured registry credentials — the same way `Attach`, `GetAttachedContent`, and `GetContentByDigest` already do.

**Why this priority**: This is the only scenario. It's a bug fix that restores consistent authentication behavior across all `OCIStore` methods. Without this fix, registry-authenticated callers would fail when retrieving artifacts without an explicit image name.

**Independent Test**: Can be tested by setting up a test registry with basic authentication, creating an OCIStore without explicit auth options (so it relies on `docker_registry` default auth), and calling `GetAttachedContentAny` — the method should succeed in pulling the artifact.

**Acceptance Scenarios**:

1. **Given** a registry that requires authentication, **When** an `OCIStore` is created without explicit `remote.Option` parameters and `GetAttachedContentAny` is called, **Then** the method uses the default `docker_registry` authentication and successfully retrieves the artifact content
2. **Given** a registry that requires authentication, **When** an `OCIStore` is created with explicit `remote.Option` parameters and `GetAttachedContentAny` is called, **Then** the method uses the explicit options (existing behavior preserved)
3. **Given** an anonymous (public) registry, **When** `GetAttachedContentAny` is called without explicit options, **Then** the method succeeds with the default anonymous auth from `docker_registry`

### Edge Cases

- What happens when `docker_registry` is not initialized? — The `RemoteOptionsForHost` call will return an error, which propagates through `remoteOptions`
- What happens when `DOCKER_CONFIG` points to a missing file? — The `docker_registry` layer handles this by falling through to its standard configuration resolution
- What happens when the default auth credentials are insufficient for the target registry? — The same behavior as any other method; the registry returns 401/403 and the error propagates

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: `OCIStore.GetAttachedContentAny` MUST use the same authentication as all other `OCIStore` methods — falling back to `docker_registry` default auth when no explicit `remote.Option` is configured
- **FR-002**: `OCIStore.GetAttachedContentAny` MUST still respect explicitly provided `remote.Option` parameters when they are passed at construction time
- **FR-003**: The authentication behavior of `GetAttachedContentAny` MUST be consistent with `Attach`, `GetAttached`, `GetAttachedContent`, and `GetContentByDigest`

### Go-Specific Requirements *(when applicable)*

- All public functions MUST accept `context.Context` as the first parameter
- Errors MUST be wrapped with `fmt.Errorf("doing something: %w", err)`
- Use `samber/lo` helpers where appropriate

### Key Entities

- **OCIStore**: Abstraction over OCI artifact attachment and retrieval using the fallback index mechanism
- **remoteOptions(ctx)**: Helper method on `OCIStore` that returns either explicit auth options or falls back to `docker_registry` default auth
- **docker_registry**: Global registry authentication provider supporting Docker config, EC2 ECR, and other auth mechanisms
- **Fallback Index**: An OCI image index (manifest list) pushed under a tag `sha256-<hex>` that references OCI artifacts attached to the parent image digest

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: `OCIStore.GetAttachedContentAny` works with registries requiring authentication when no explicit auth options are provided — integration test passes
- **SC-002**: All existing attestation and SBOM tests continue to pass without modification — no regression
- **SC-003**: The fix is consistent across all four `OCIStore` methods: no other method uses `s.opts` directly without the `remoteOptions` fallback

## Assumptions

- The global `docker_registry` API is properly initialized before any registry operations — this is already handled in the existing codebase
- Registries requiring authentication are the norm for production usage — the fix ensures consistency across all retrieval paths
- The `remoteOptions` helper method correctly handles both empty and non-empty option slices — verified by existing usage across other methods
- `GetAttachedContentAny` callers (`pkg/attestation/get.go`, `pkg/sbom/image/image.go`) do not currently work around the bug by redundantly passing auth options — the fix removes the need for any workaround