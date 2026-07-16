# Feature Specification: Collect All Failing Components During External Ref Enrichment

**Feature Branch**: `feat/sbom/collect-external-ref-errors`

**Created**: 2026-07-16

**Status**: migrated

**Input**: Reverse-engineered from existing code in `pkg/sbom/externalref/`

## Project Context

**Delivery Kit** is a Go CLI tool for full-cycle CI/CD to Kubernetes. It is built on top of werf with Deckhouse Platform extensions. Key subsystems:

- **Build** (`pkg/build/`) — Container image building via Buildah
- **Deploy** (`pkg/deploy/`) — Kubernetes deployment via werf/nelm (Helm-based)
- **SBOM** (`pkg/sbom/`) — Software Bill of Materials generation and validation
- **Cleanup** (`pkg/cleaning/`) — Container registry cleanup policies
- **Signature** (`pkg/signature/`) — Container image signing and verification
- **Docker Registry** (`pkg/docker_registry/`) — OCI registry operations
- **Config** (`pkg/config/`) — werf.yaml configuration parsing

The SBOM subsystem includes an `externalref` package that enriches CycloneDX BOM components with external reference URLs (VCS, website, issue tracker, etc.) by resolving their Package URLs (PURLs) through an external service.

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Complete External Ref Enrichment Despite Partial Failures (Priority: P1)

A user building container images with SBOM generates a BOM with hundreds of components. Some components have unresolvable PURLs (unknown packages, missing data, network errors). The user expects that resolvable components are still enriched with external references, and all failures are reported in a single aggregated error so they can identify and fix all problematic components in one pass rather than iterating through failures one at a time.

**Why this priority**: This is the sole use case — collecting all failures instead of stopping at the first one. Without this, a BOM with 100 components where 5 have bad PURLs requires 5 rebuild cycles to discover all failures.

**Independent Test**: Can be fully tested by creating a BOM with multiple components that fail enrichment and verifying that: (a) all components are attempted, (b) the error message reports the total count of failures, (c) each individual failure detail is logged.

**Acceptance Scenarios**:

1. **Given** a BOM with multiple components, some of which have unresolvable PURLs, **When** the Enricher processes the BOM, **Then** all components SHALL be attempted for enrichment regardless of individual failures
2. **Given** multiple components failed enrichment, **When** processing completes, **Then** the error SHALL contain the aggregated message `"resolve external references: N of M components failed"` where `N` is the count of failed components and `M` is the total count
3. **Given** a mix of failing and succeeding components, **When** enrichment completes, **Then** succeeding components SHALL still have their external references appended
4. **Given** the same PURL resolves for multiple components, **When** enrichment completes, **Then** the BOM-level external references SHALL be deduplicated

---

### Edge Cases

- Nil BOM or nil components slice returns nil error (early return) — unchanged behavior
- Empty components slice returns nil error — unchanged behavior
- OS type components without PURLs are skipped (not errors) — unchanged behavior
- Components with version `"(devel)"` are skipped — unchanged behavior
- All components failing produces error with full count (e.g., `"2 of 2 components failed"`)
- Single component failing produces error with count of 1 (e.g., `"1 of 1 components failed"`)

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: The Enricher MUST process all components in the BOM regardless of individual enrichment failures
- **FR-002**: When one or more components fail enrichment, the Enricher MUST return an aggregated error with the format `"resolve external references: N of M components failed"`
- **FR-003**: The Enricher MUST log each failed component via `logboek.Error()` with its name, PURL, and error message
- **FR-004**: Successful enrichment of individual components MUST still apply external references even when other components fail
- **FR-005**: BOM-level deduplication of external references MUST still occur after enrichment regardless of partial failures
- **FR-006**: The `ExternalRefPatcher.Apply` wrapper MUST still return the original BOM on error (unchanged contract)

### Go-Specific Requirements *(when applicable)*

- All public functions MUST accept `context.Context` as the first parameter
- Errors MUST be wrapped with `fmt.Errorf("doing something: %w", err)`
- Use `samber/lo` helpers (`lo.Compact`, etc.) where appropriate
- Optional arguments use `<FunctionName>Options` struct — never functional options

### Key Entities

- **Enricher**: The core type that enriches a CycloneDX BOM with external references by resolving component PURLs through the external service
- **ComponentError**: Internal type (unexported) used to collect per-component enrichment failures: `{name, purl, err}`
- **ResolveResult**: Response from the external resolve service containing the resolved URL, reference kind, and metadata
- **ExternalRefPatcher**: Wrapper that exposes `Enricher.Enrich` as an `Apply(ctx, *cdx.BOM) (*cdx.BOM, error)` method for use in the build pipeline

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: A BOM with N failing components produces a single aggregated error reporting `"N of M components failed"` — verified by unit tests
- **SC-002**: A BOM with a mix of failing and succeeding components produces external references on the succeeding components — verified by unit tests
- **SC-003**: All components are attempted regardless of failures — verified by test case with 2 failing components producing `"2 of 2 components failed"`
- **SC-004**: The `ExternalRefPatcher` contract (return original BOM on error) is preserved — verified by unit test
- **SC-005**: No regression for the happy path — all components with valid PURLs are enriched without error

## Assumptions

- The external resolve service is configured via the `WERF_EXTERNAL_REFS_SERVER_URL` environment variable
- Concurrency is limited to 10 goroutines (via `errgroup.Group.SetLimit(10)`)
- Components without PURLs and of known non-library types (OS, Device, File, Firmware, etc.) are expected to be skipped
- The `ExternalRefPatcher.Apply` contract explicitly returns the original BOM on error, allowing the build pipeline to continue with best-effort results
- Error context wrapping in `patcher.go` adds `"enrich external references: ..."` prefix to the aggregated error