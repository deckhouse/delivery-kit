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

The Build subsystem processes container images in dependency order via image sets. During SBOM generation, each image's components are enriched with external references by resolving their Package URLs (PURLs) through an external service. The enrichment operates at two levels:

- **Component level** (`pkg/sbom/externalref/enricher.go`): `Enricher.Enrich` resolves PURLs for every component within a single image's BOM. On failure, it returns a `*ComponentError` containing individual component failure details inline in the error text (e.g., `"resolve external references: components failed:\n    - component: curl: resolve \"pkg:generic/curl@8.12.1\": ..."`). The `logboek.Error()` logging for individual component failures has been removed — the error text is the sole carrier of failure details.
- **Image level** (`pkg/build/build_phase.go`): `convergeImageSbom` calls `ExternalRefPatcher.Apply` which wraps the enricher error. Error detection uses the sentinel error `ErrExternalRefEnrich` via `errors.Is`. The build phase accumulates PURL errors across all images in all sets and returns a single hierarchical aggregated error.

A build may involve many images, and the PURL resolver can fail for some or all of them.

## User Scenarios & Testing *(mandatory)*

### User Story 1 - See All PURL Resolution Failures in a Single Build (Priority: P1)

A user building container images has a `werf.yaml` that defines multiple images. Some images reference packages whose PURLs cannot be resolved by the external service (unknown packages, missing data, network errors). The user expects the build to complete PURL resolution for ALL images, collect ALL failures, and report them in a single aggregated message — so they can identify all problematic images and update the component database in one pass rather than iterating through failures one at a time per rebuild.

**Why this priority**: This is the core use case. With N images and M of them having unresolvable PURLs, the user currently needs up to M rebuild cycles to discover all failures. Collecting all errors in one pass collapses this to a single cycle.

**Independent Test**: Can be fully tested by creating a project with multiple images where a subset has unresolvable PURLs, running the build, and verifying that: (a) all images are attempted for PURL resolution regardless of individual failures, (b) the build fails with a single hierarchical aggregated error listing all image-level failures, (c) each image-level failure includes the image name prefixed with `"  - image:"` and each component failure detailed as `"    - component: <name>: <error>"`.

**Acceptance Scenarios**:

1. **Given** a project with multiple images where some images fail PURL resolution, **When** the build processes SBOM generation, **Then** ALL images SHALL be attempted for PURL resolution regardless of individual failures
2. **Given** multiple images failed PURL resolution, **When** the build completes the SBOM phase, **Then** the error SHALL contain a hierarchical aggregated message with the format:
   ```
   resolve external references: N of M images failed:
     - image: <image-name>:
       - component: <component-name>: <error>
       - component: <component-name>: <error>
     - image: <image-name>:
       - component: <component-name>: <error>
   ```
3. **Given** a mix of failing and succeeding images, **When** the build completes the SBOM phase, **Then** succeeding images SHALL have their SBOMs fully generated and saved
4. **Given** all images pass PURL resolution, **When** the build completes the SBOM phase, **Then** no error SHALL be returned (no behavioral regression)

### User Story 2 - E2E: Three Images with Mixed PURL Failures (Priority: P2)

A project has three images in `werf.yaml`. The e2e test verifies that all images are processed, failures are collected across all images, and the final aggregated error contains all details. The test uses a custom `httptest.Server` mock to simulate PURL resolution 404 failures for specific packages (`curl`, `openssl`) and success for others (`jq`).

**Test scenario**:
- Image 1: `image-fail-all` — 2 OS PM packages: `curl==8.12.1` and `openssl==3.6.2`, both fail PURL resolution (404)
- Image 2: `image-fail-partial` — 2 OS PM packages: `curl==8.12.1` (fails) and `jq==1.8.1` (succeeds)
- Image 3: `image-ok` — 1 OS PM package: `jq==1.8.1` (succeeds)

**Why this priority**: This is the primary acceptance test that validates end-to-end behavior of the feature: all images attempted, failure details carry through component→image→build level, succeeding images are unaffected.

**Independent Test**: Implemented as a Ginkgo e2e test in a separate test file at `test/e2e/sbom/purl_resolver_errors_test.go`. The test creates a repo with the three-image `werf.yaml`, starts a custom httptest mock that returns 404 for `curl`/`openssl` and 200 for `jq`, runs `werf build`, and asserts that:
- The build fails with a single aggregated error containing `"resolve external references"` prefix
- The aggregated error contains `"  - image: image-fail-all"` and `"  - image: image-fail-partial"`
- The aggregated error lists component names `curl` and `openssl` with their PURL and error details
- The aggregated error does NOT contain `"image: image-ok"`
- The `image-ok` SBOM is produced with valid external references

**Acceptance Scenarios**:

1. **Given** a project with 3 images where image 1 has 2/2 OS PM failures, image 2 has 1/2 OS PM failures, and image 3 has 0/1 OS PM failures, **When** the build completes SBOM generation, **Then** the build SHALL fail with a single aggregated error
2. **Given** the aggregated build error, **When** inspecting its text, **Then** it SHALL contain `"  - image: image-fail-all"` with 2 component failures, `"  - image: image-fail-partial"` with 1 component failure, and SHALL NOT contain `"image: image-ok"`
3. **Given** the build failure, **When** inspecting the `image-ok` SBOM, **Then** it SHALL have been successfully generated with valid external references

---

### Edge Cases

- Single image project with failing PURL: aggregated error shows `"resolve external references: 1 of 1 images failed:"` with hierarchical format
- All images failing: aggregated error shows `"resolve external references: N of N images failed:"` with all image details
- `ExternalRefPatcher` construction errors (missing env var) are NOT aggregated — they are pre-condition failures that should stop the build immediately
- Non-PURL errors in `convergeImageSbom` (e.g., base image collection failure) are NOT aggregated — they fail the build immediately; only `errors.Is(err, ErrExternalRefEnrich)` errors are accumulated
- Empty image sets: no error (unchanged behavior)
- Multiple image sets: errors from ALL sets are accumulated into a single aggregated error

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: The build MUST process ALL images for PURL resolution regardless of individual image failures
- **FR-002**: When one or more images fail PURL resolution, the build MUST return a single hierarchical aggregated error WITHIN THE ENTIRE BUILD with the format:
  ```
  resolve external references: N of M images failed:
    - image: <image-name>:
      - component: <component-name>: <error>
  ```
  where `N` is the count of failed images across all image sets, `M` is the total image count across all image sets, and each image section lists the failing component details.
- **FR-003**: The error returned by `Enricher.Enrich` at the component level MUST be a `*ComponentError` type that carries individual component failure details inline in the error text with the format `"resolve external references: components failed:\n    - component: <name>: <error>\n..."`. The `ComponentError` MUST expose a `ComponentDetails()` method returning the raw failure detail lines for build-level aggregation.
- **FR-004**: The `logboek.Error().LogF(...)` calls in `Enricher.Enrich` for individual component failures MUST be removed — the error text is the sole carrier of failure details.
- **FR-005**: Successful PURL resolution of individual images MUST still produce valid SBOMs even when other images fail
- **FR-006**: Pre-condition failures (missing environment variables, configuration errors) MUST NOT be aggregated — they SHALL fail the build immediately as before
- **FR-007**: The aggregation MUST be performed once for the entire build, collecting failures from ALL image sets. Image sets MUST still be processed sequentially to respect dependency order.
- **FR-008**: Empty image sets SHALL be handled without error and contribute no failures (no behavioral change)
- **FR-009**: The `ExternalRefPatcher.Apply` method MUST wrap the enricher error with `errors.Join(err, ErrExternalRefEnrich)` so that the build phase can detect PURL resolution errors via `errors.Is(err, ErrExternalRefEnrich)`.

### Go-Specific Requirements *(when applicable)*

- All public functions MUST accept `context.Context` as the first parameter
- Errors MUST be wrapped with `fmt.Errorf("doing something: %w", err)`
- Use `samber/lo` helpers (`lo.Compact`, etc.) where appropriate
- Optional arguments use `<FunctionName>Options` struct — never functional options
- The `Enricher.Resolve` field is public, allowing tests to inject a mock resolve function directly without relying on the HTTP service mock
- The `Enricher` constructor (`NewEnricher`) sets the `Resolve` field
- The `ComponentError` type implements `Error()` and `Unwrap()` and exposes a `ComponentDetails()` method
- The sentinel error `ErrExternalRefEnrich` is defined in `pkg/sbom/externalref/` for `errors.Is` detection

### Key Entities

- **Image Set**: A group of images that can be processed in parallel (same dependency level in the build graph). Image sets are processed sequentially.
- **Parallel Task**: Individual image processing within a set, executed concurrently via `parallel.DoTasks`.
- **Purl Resolution Error**: An error detected via `errors.Is(err, ErrExternalRefEnrich)` from `ExternalRefPatcher.Apply` when the external PURL resolution service fails for a particular image.
- **ComponentError** (`pkg/sbom/externalref/`): Error type returned by `Enricher.Enrich` containing individual component failure details. Provides `ComponentDetails()` method returning raw detail lines for build-level aggregation.
- **ErrExternalRefEnrich** (`pkg/sbom/externalref/`): Sentinel error used for `errors.Is` detection in the build phase.
- **Aggregated Build Error**: A hierarchical error that collects all PURL resolution failures from all images across all image sets and presents them in the format:
  ```
  resolve external references: N of M images failed:
    - image: <image-name>:
      - component: <component-name>: <error>
  ```

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: A build with N images and M PURL failures produces a single hierarchical aggregated error with the format `"resolve external references: N of M images failed:"` containing image and component details — verified by unit tests
- **SC-002**: A build with a mix of failing and succeeding images produces valid SBOMs on the succeeding images — verified by unit tests
- **SC-003**: All images are attempted for PURL resolution regardless of failures — verified by test with 2 failing images
- **SC-004**: The error from `Enricher.Enrich` is a `*ComponentError` with format `"resolve external references: components failed:\n    - component: <name>: <error>\n..."` — verified by unit test asserting error string content
- **SC-005**: `Enricher.Enrich` does not log individual component failures via `logboek` — verified by unit test that checks no `logboek.Error` output for failure details
- **SC-006**: The user sees the complete list of failures in the build output in a single hierarchical aggregated error — verified by integration test
- **SC-007**: No regression for the happy path — all images with valid PURLs build successfully without error
- **SC-008**: The e2e test scenario with 3 images (2/2 failures, 1/2 failures, 0/1 failures) passes — verified by running `task test:e2e -- paths="./test/e2e/sbom/..." labelFilter="purl-resolver-errors"`
- **SC-009**: The e2e test file for batch PURL resolution errors is placed as a separate file at `test/e2e/sbom/purl_resolver_errors_test.go` and uses a custom `httptest.Server` mock to simulate component-level failures
- **SC-010**: The `Enricher.Resolve` field is public and can be injected directly via `NewEnricher` or by setting the field on a zero-value `Enricher` struct — verified by unit tests

## Assumptions

- The PURL resolution error originates from `ExternalRefPatcher.Apply` and is detected via `errors.Is(err, ErrExternalRefEnrich)`
- The build uses `parallel.DoTasks` (from `pkg/build/parallel/`) for concurrent image processing within a set
- The user's component database is maintained externally and is not part of this feature
- Only errors specifically from PURL resolution (external reference enrichment) are aggregated; other SBOM phase errors (scanning, merging) still fail per-image
- The `ExternalRefPatcher` contract (return BOM on error) is preserved and can be relied upon for best-effort results
- The `Enricher.Enrich` method in `pkg/sbom/externalref/enricher.go` returns `*ComponentError` with inline component failure details, replacing the previous `logboek`-only reporting of individual failures
- The `buildAggregatedPurlError` helper function in `pkg/build/build_phase.go` builds the hierarchical error format by iterating over accumulated component details stored in a `sync.Map` with image names as keys