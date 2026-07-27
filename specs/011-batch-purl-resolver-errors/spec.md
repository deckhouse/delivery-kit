# Feature Specification: Batch Purl-Resolver Errors

**Feature Branch**: `feat/build/batch-purl-resolver-errors`

**Created**: 2026-07-27

**Status**: Draft

**Input**: User description: "Сейчас purl-resolver возвращает ошибки для каждого образа и сборка останавливается. После остановки сборки пользователь берет выведенные ошибки (компонентов) и вносит их в базу данных компонентов, чтобы не следующем перезапуске ошибок для этих компонентов уже не появлялось. Получается, что путь и время получения обратной связи пользователем удлинняются за счет количества образов в сборке. Необходимо сократить время получения обратной связи пользователем. Выводить сразу все ошибки от purl-resolver(а) для всех образов."

## Project Context

**Delivery Kit** is a Go CLI tool for full-cycle CI/CD to Kubernetes. It is built on top of werf with Deckhouse Platform extensions. Key subsystems:

- **Build** (`pkg/build/`) — Container image building via Buildah
- **Deploy** (`pkg/deploy/`) — Kubernetes deployment via werf/nelm (Helm-based)
- **SBOM** (`pkg/sbom/`) — Software Bill of Materials generation and validation
- **Cleanup** (`pkg/cleaning/`) — Container registry cleanup policies
- **Signature** (`pkg/signature/`) — Container image signing and verification
- **Docker Registry** (`pkg/docker_registry/`) — OCI registry operations
- **Config** (`pkg/config/`) — werf.yaml configuration parsing

The Build subsystem processes container images in dependency order via image sets. During SBOM generation, each image's components are enriched with external references by resolving their Package URLs (PURLs) through an external service (`ExternalRefPatcher` in `pkg/sbom/externalref/`). A build may involve many images, and the PURL resolver can fail for some or all of them.

## User Scenarios & Testing *(mandatory)*

### User Story 1 - See All PURL Resolution Failures in a Single Build (Priority: P1)

A user building container images has a `werf.yaml` that defines multiple images. Some images reference packages whose PURLs cannot be resolved by the external service (unknown packages, missing data, network errors). The user expects the build to complete PURL resolution for ALL images, collect ALL failures, and report them in a single aggregated message — so they can identify all problematic images and update the component database in one pass rather than iterating through failures one at a time per rebuild.

**Why this priority**: This is the core use case. With N images and M of them having unresolvable PURLs, the user currently needs up to M rebuild cycles to discover all failures. Collecting all errors in one pass collapses this to a single cycle.

**Independent Test**: Can be fully tested by creating a project with multiple images where a subset has unresolvable PURLs, running the build, and verifying that: (a) all images are attempted for PURL resolution regardless of individual failures, (b) the build fails with a single aggregated error listing all failures, (c) each failure includes the image name and the underlying error detail.

**Acceptance Scenarios**:

1. **Given** a project with multiple images where some images fail PURL resolution, **When** the build processes SBOM generation, **Then** ALL images SHALL be attempted for PURL resolution regardless of individual failures
2. **Given** multiple images failed PURL resolution, **When** the build completes the SBOM phase, **Then** the error SHALL contain an aggregated message reporting the count of failed images and the total image count, with each failure detail listed in the error text
3. **Given** a mix of failing and succeeding images, **When** the build completes the SBOM phase, **Then** succeeding images SHALL have their SBOMs fully generated and saved
4. **Given** all images pass PURL resolution, **When** the build completes the SBOM phase, **Then** no error SHALL be returned (no behavioral regression)

---

### Edge Cases

- Single image project with failing PURL: aggregated error shows "1 of 1 images failed"
- All images failing: aggregated error shows "N of N images failed"
- `ExternalRefPatcher` construction errors (missing env var) are NOT aggregated — they are pre-condition failures that should stop the build immediately
- Non-PURL errors in `convergeImageSbom` (e.g., base image collection failure) may still stop the build for that specific image; only PURL resolution errors are accumulated

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: The build MUST process ALL images for PURL resolution regardless of individual image failures
- **FR-002**: When one or more images fail PURL resolution, the build MUST return a single aggregated error WITHIN THE ENTIRE BUILD with the format `"resolve external references: N of M images failed"` where `N` is the count of failed images across all image sets and `M` is the total image count across all image sets
- **FR-003**: Successful PURL resolution of individual images MUST still produce valid SBOMs even when other images fail
- **FR-004**: Pre-condition failures (missing environment variables, configuration errors) MUST NOT be aggregated — they SHALL fail the build immediately as before
- **FR-005**: The aggregation MUST be performed once for the entire build, collecting failures from ALL image sets. Image sets MUST still be processed sequentially to respect dependency order.
- **FR-006**: Empty image sets SHALL be handled without error and contribute no failures (no behavioral change)

### Go-Specific Requirements *(when applicable)*

- All public functions MUST accept `context.Context` as the first parameter
- Errors MUST be wrapped with `fmt.Errorf("doing something: %w", err)`
- Use `samber/lo` helpers (`lo.Compact`, etc.) where appropriate
- Optional arguments use `<FunctionName>Options` struct — never functional options

### Key Entities

- **Image Set**: A group of images that can be processed in parallel (same dependency level in the build graph). Image sets are processed sequentially.
- **Parallel Task**: Individual image processing within a set, executed concurrently via `parallel.DoTasks`.
- **Purl Resolution Error**: An error returned by `ExternalRefPatcher.Apply` when the external PURL resolution service fails for a particular image.
- **Aggregated Build Error**: A combined error that collects all PURL resolution failures from all images across all image sets and presents them as a single error message for the entire build.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: A build with N images and M PURL failures produces a single aggregated error reporting `"resolve external references: M of N images failed"` — verified by unit tests
- **SC-002**: A build with a mix of failing and succeeding images produces valid SBOMs on the succeeding images — verified by unit tests
- **SC-003**: All images are attempted for PURL resolution regardless of failures — verified by test with 2 failing images producing `"2 of 2 images failed"`
- **SC-004**: The user sees the complete list of failures in the build output in a single aggregated error — verified by integration test
- **SC-005**: No regression for the happy path — all images with valid PURLs build successfully without error
- **SC-006**: Feedback loop time is reduced proportionally to the number of failing images — a 5-image build with 3 failures requires 1 rebuild instead of up to 3 rebuilds

## Assumptions

- The PURL resolution error originates from `ExternalRefPatcher.Apply` and is wrapped as `"enrich external references: ..."`
- The build uses `parallel.DoTasks` (from `pkg/build/parallel/`) for concurrent image processing within a set
- The user's component database is maintained externally and is not part of this feature
- Only errors specifically from PURL resolution (external reference enrichment) are aggregated; other SBOM phase errors (scanning, merging) still fail per-image
- The existing `ExternalRefPatcher` contract (return BOM on error) is already implemented and can be relied upon for best-effort results
