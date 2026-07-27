# Feature Specification: Reduce PURL Resolver Retries Duration

**Feature Branch**: `011-reduce-purl-retries-duration`

**Created**: 2026-07-27

**Status**: Draft

**Input**: User description: "retries to purl-resolver are too long, want to make them shorter"

## Retry Parameters

In the worst case a single PURL resolution takes up to **30 s** — the current `MaxElapsedTime` before the system gives up. The sole HTTP request timeout (`HTTPClient.Timeout`) is also 30 s, meaning a single hung request can exhaust the entire retry budget with no retries attempted.

Target: **10 s** — a 3× reduction. The HTTP request timeout is lowered to 5 s so that a slow request does not consume the entire retry budget, leaving room for actual retries when the server responds quickly but with transient errors.

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

### User Story 1 - Reduce PURL resolution wait time for SBOM enrichment (Priority: P1)

As a user running `werf sbom` generation, when an SBOM component needs PURL-to-external-reference resolution but the resolution service is temporarily slow or unresponsive, I want the retry mechanism to fail faster so that the entire SBOM generation process does not stall for tens of seconds waiting for resolution failures.

**Why this priority**: This directly affects the user's experience with the `werf sbom` command. Currently, each PURL can retry for up to 30 seconds before failing (see Retry Parameters section), and multiple components are resolved in parallel (up to 10 at a time). Reducing the retry time speeds up the overall feedback loop for the user.

**Independent Test**: Can be fully tested by setting up a mock PURL resolution server that returns 429 or 5xx status codes, verifying that the resolution fails (after retries) within the target 10 s (see Retry Parameters section) rather than the current 30 s.

**Acceptance Scenarios**:

1. **Given** an SBOM component with a valid PURL, **When** the external PURL resolution service returns 429 (Too Many Requests) for the first attempts, **Then** the system retries the resolution but fails within the target `MaxElapsedTime` (10 s, see Retry Parameters section).
2. **Given** an SBOM component with a valid PURL, **When** the external PURL resolution service returns 503 (Service Unavailable), **Then** the system retries the resolution but fails within the target `MaxElapsedTime`.

---

### User Story 2 - Predictable failure behavior in CI/CD pipelines (Priority: P2)

As a CI/CD pipeline operator, when the PURL resolution service is unavailable, I want the retry to complete quickly so that the pipeline fails fast with a clear error rather than consuming time waiting.

**Why this priority**: CI/CD pipelines are sensitive to total runtime. Faster retry exhaustion means the pipeline can report the resolution error and either retry at a higher level (job level) or proceed with degraded SBOM metadata more quickly.

**Independent Test**: Can be tested by configuring the resolution service to be completely unreachable and measuring the time until the enrichment operation reports an error.

**Acceptance Scenarios**:

1. **Given** a CI/CD pipeline running `werf sbom`, **When** the PURL resolution service is completely unreachable, **Then** the enrichment operation completes (with error) within the target `MaxElapsedTime` (10 s, see Retry Parameters section) for each component.
2. **Given** a CI/CD pipeline running `werf sbom`, **When** some components fail PURL resolution, **Then** the user sees clear warning messages for each failed component within the shorter retry window.

---

### Edge Cases

- What happens when the PURL resolution server responds but with degraded performance on every request? The retry budget should be exhausted within the target `MaxElapsedTime`, not the current 30-second limit.
- How does the system behave when some components resolve successfully and others fail? Enrichment of other components should not be delayed by retries on failing components — parallel execution with independent retry budgets per component ensures isolation.

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: System MUST apply the target `MaxElapsedTime` (10 s, see Retry Parameters section) as the maximum retry duration per PURL.
- **FR-002**: System MUST apply the target `InitialInterval`, `Multiplier`, and `MaxInterval` from the Retry Parameters section for the exponential backoff strategy.
- **FR-003**: System MUST set the HTTP client timeout to the target value (5 s, see Retry Parameters section), so that the total wait time per PURL does not exceed the retry budget.
- **FR-004**: System MUST continue to log warning messages during retries so that users are informed about transient failures.
- **FR-005**: Failed resolutions MUST still be reported as aggregated errors after enrichment, preserving the existing error reporting behavior.

### Go-Specific Requirements *(when applicable)*

- All public functions MUST accept `context.Context` as the first parameter
- Errors MUST be wrapped with `fmt.Errorf("doing something: %w", err)`
- Use `samber/lo` helpers (`lo.Filter`, `lo.Map`, `lo.Contains`, etc.) where appropriate
- Optional arguments use `<FunctionName>Options` struct — never functional options
- Add `var _ Interface = (*Impl)(nil)` compile-time check for each interface implementation

### Key Entities *(include if feature involves data)*

- **ExternalRef Service**: HTTP client that communicates with the PURL resolution service, managing request timeouts and retry logic
- **Enricher**: Orchestrates parallel PURL resolution for SBOM components, calling the service for each component

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: Total retry window per PURL resolution attempt matches the target `MaxElapsedTime` (10 s, see Retry Parameters section).
- **SC-002**: SBOM enrichment with a fully failing resolution service reports an error to the user within the target `MaxElapsedTime` (10 s) per PURL (accounting for parallel execution).
- **SC-003**: Successful resolutions on transient failures (recover within 1-2 retries) continue to succeed without user-perceptible change in behavior.
- **SC-004**: Warning messages during retries are preserved and visible to the user.

## Assumptions

- The current and target retry parameters are documented in the Retry Parameters section.
- The existing exponential backoff strategy should be preserved — only the parameter values change.
- The HTTP request timeout should be aligned with the target `MaxElapsedTime` to avoid waiting for a slow request that would consume most of the retry window.
- The parallel resolution behavior (up to 10 concurrent requests) and the existing error aggregation logic should be preserved unchanged.