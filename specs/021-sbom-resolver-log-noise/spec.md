# Feature Specification: Quiet PURL Resolver Log Noise

**Feature Branch**: `fix/sbom/quiet-resolver-http-errors`

**Created**: 2026-09-03

**Status**: Implemented

**Input**: User description: "В секции генерации SBOM при резолве зависимостей лог заваливается HTML-страницами nginx (502 Bad Gateway) на каждый компонент, повторяющимися одинаковыми строками и полными отчётами упавшего образа внутри предупреждений соседних образов. Убрать шум, не снизив информативность лога."

## Project Context

**Delivery Kit** is a Go CLI tool for full-cycle CI/CD to Kubernetes. It is built on top of werf with Deckhouse Platform extensions. Key subsystems:

- **Build** (`pkg/build/`) — Container image building via Buildah
- **Deploy** (`pkg/deploy/`) — Kubernetes deployment via werf/nelm (Helm-based)
- **SBOM** (`pkg/sbom/`) — Software Bill of Materials generation and validation
- **Cleanup** (`pkg/cleaning/`) — Container registry cleanup policies
- **Signature** (`pkg/signature/`) — Container image signing and verification
- **Docker Registry** (`pkg/docker_registry/`) — OCI registry operations
- **Config** (`pkg/config/`) — werf.yaml configuration parsing

During SBOM converge, each image's components are enriched with external references by resolving Package URLs (PURLs) through an external HTTP service (`WERF_EXTERNAL_REFS_SERVER_URL`, `pkg/sbom/externalref/`). Failure semantics are defined by spec `011-batch-purl-resolver-errors` (per-image `ComponentError` with per-component detail lines, build-level aggregation) and spec `017-sbom-converge-failure-semantics` (content vs infrastructure failure classes, the process-wide `ResolverBreaker` that latches after 5 consecutive infrastructure failures, and the single terminal `PURL resolver unavailable at <endpoint>: <last infra error>` error). Images of one dependency level converge in parallel workers whose logs are buffered and flushed together; the worker group cancels the shared context with the first failure as the cancellation cause.

This feature fixes four independent log-noise amplifiers observed on a real CI job where the resolver sat behind a proxy and returned 502 (~2300 log lines in one second for one resolver outage):

1. Raw HTTP response bodies (multi-line nginx HTML pages) embedded verbatim into every resolve error.
2. The context cancellation cause (the first failed image's entire error report) re-entering sibling images' warnings as a single "component error", recursively multiplying the report per image.
3. Merged BOMs (base + imports + os-pm) carrying the same component several times: each duplicate was resolved separately (duplicate HTTP requests with their own retry cycles) and reported separately (identical lines).
4. After the breaker tripped, every remaining component line was annotated with the endpoint and the breaker's last infrastructure error — an error belonging to a *different* PURL.

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Diagnose a Resolver Outage from a Readable Log (Priority: P1)

A user runs a build with SBOM enabled while the external references resolver misbehaves (returns 5xx through a proxy, times out, or goes down mid-build). The user opens the CI log and expects a compact SBOM failure section: one short line per real failure, one summary for the outage, one terminal error naming the endpoint and the last real infrastructure error — instead of thousands of lines of proxy HTML boilerplate and repeated reports.

**Why this priority**: This is the observed incident. The noise buries the actual root cause, makes CI log pages slow to load, and the per-component HTML repetition carries zero information beyond the HTTP status line.

**Independent Test**: Point `WERF_EXTERNAL_REFS_SERVER_URL` at a mock returning `502` with an HTML body for every PURL, run a multi-image build, and verify the SBOM section contains no `<html>` fragments, no repeated full reports, and exactly one terminal resolver-unavailable error.

**Acceptance Scenarios**:

1. **Given** the resolver answers a PURL with a non-200 status and an HTML body, **When** the resolve error is reported, **Then** the error SHALL read `resolve: unexpected status <status line>` (e.g. `resolve: unexpected status 502 Bad Gateway`) and SHALL NOT contain any part of the HTML body
2. **Given** the resolver answers a PURL with a non-200 status and a non-HTML body (e.g. a JSON error), **When** the resolve error is reported, **Then** the body SHALL be preserved collapsed to a single line and truncated at 200 characters
3. **Given** one image's SBOM converge failed terminally and the worker group canceled the shared context, **When** a sibling image's in-flight resolution aborts, **Then** its error SHALL read `resolve: context canceled` and SHALL NOT embed the failed image's error report
4. **Given** the breaker tripped mid-build, **When** the build fails, **Then** the terminal error SHALL name the endpoint and the last *real* infrastructure error (e.g. the 502), not `context canceled`

---

### User Story 2 - No Duplicate Lines or Requests for Duplicated Components (Priority: P2)

A user builds an image whose merged BOM (base image + imports + os-pm packages) contains the same component several times. Failures for that component appear once in the warning, and the resolver receives one request for that PURL instead of one per duplicate (each with its own retry budget).

**Why this priority**: Duplication multiplies both log noise and load on the resolver; on the observed job single components were resolved and reported four times per image.

**Independent Test**: Enrich a BOM containing the same PURL in three components against a counting mock: exactly one resolve call is made; on failure the warning contains the PURL exactly once; on success all three components receive the external reference.

**Acceptance Scenarios**:

1. **Given** a BOM with the same PURL in N components, **When** enrichment runs, **Then** the resolver SHALL receive exactly one request for that PURL
2. **Given** that PURL fails resolution, **When** the per-image warning is rendered, **Then** it SHALL contain exactly one `- component:` line for that PURL
3. **Given** that PURL resolves successfully, **When** enrichment completes, **Then** every duplicate component SHALL carry the resolved external reference and BOM-level references SHALL stay deduplicated

---

### User Story 3 - Correct Attribution After the Breaker Trips (Priority: P3)

A user reads the failure report after the resolver became unavailable mid-build. Components that were never actually resolved (the breaker rejected them) do not masquerade as individual failures annotated with another PURL's error; they are summarized in one line, and the endpoint with the last real error appears exactly once — in the terminal error.

**Why this priority**: Misattribution actively misleads debugging (the log showed `component: C5 (pkg:nuget/C5@...)` annotated with a request URL for `pkg:generic/go@...`), but it only occurs after the breaker trips, which User Story 1 already makes survivable.

**Independent Test**: Trip the breaker, enrich a BOM with several unresolved PURLs, and verify the warning contains a single summary line with the skipped count and no per-component endpoint/last-error annotations.

**Acceptance Scenarios**:

1. **Given** a tripped breaker, **When** a resolution is rejected, **Then** the per-PURL error SHALL be the bare sentinel `PURL resolver unavailable` without endpoint or another PURL's last error
2. **Given** N unique PURLs rejected by the tripped breaker within one image, **When** the per-image warning is rendered, **Then** they SHALL collapse into one line: `    - PURL resolver unavailable: resolution skipped for N package URLs`
3. **Given** breaker-rejected failures were grouped, **When** the build phase classifies the image error, **Then** terminality detection via the resolver-unavailable sentinel SHALL still work (the build fails with the single terminal error per spec 017)

---

### Edge Cases

- Non-200 response with an empty or whitespace-only body: error carries the status line only
- Non-200 response with `Content-Type: text/html` but a JSON-looking body (or vice versa): a body is dropped when the content type says HTML **or** the body looks like markup (starts with `<`)
- Mixed failures in one image (content failures + breaker rejections): content failures keep their per-component lines, breaker rejections collapse into the summary line, both appear in the same warning
- Cancellation racing a real infrastructure failure: a request that failed *because* the context was canceled is reported as cancellation even if the transport error text differs; a request that completed with a real error before cancellation keeps that error
- Cancelled resolutions must not trip or feed the breaker: a build aborting for unrelated reasons does not fabricate resolver-unavailability
- A PURL duplicated across *different images* is still resolved once per image: cross-image caching is out of scope (workers would need a shared cache with its own consistency semantics)

## Requirements *(mandatory)*

### Functional Requirements

**HTTP error rendering**

- **FR-001**: A non-200 resolver response MUST be reported with the HTTP status line (code and reason phrase), e.g. `resolve: unexpected status 502 Bad Gateway`
- **FR-002**: A response body that is HTML (content type contains `text/html`, or the body starts with `<` after whitespace normalization) MUST be omitted from the error — proxy boilerplate carries nothing beyond the status line
- **FR-003**: A non-HTML, non-empty response body MUST be preserved in the error, collapsed to a single line (all whitespace runs become single spaces) and truncated at 200 characters with a `...` marker

**Cancellation isolation**

- **FR-004**: A resolution that fails while its context is canceled MUST be reported as the plain context error (`resolve: context canceled`) and MUST NOT embed the cancellation cause. Rationale: the worker group cancels siblings with the first failure as the context cause, and the HTTP client returns that cause from canceled requests — without this guard every sibling image's warning embeds the failed image's entire report
- **FR-005**: A canceled resolution MUST NOT be retried and MUST NOT count toward the resolver breaker: cancellation is terminal for the build and says nothing about resolver health. Consequently the breaker's recorded last infrastructure error stays the last *real* one and the terminal error remains informative

**PURL deduplication**

- **FR-006**: Within one image's BOM enrichment, each unique PURL MUST be resolved at most once; all duplicate components MUST share that single outcome (success or failure)
- **FR-007**: The per-image failure report MUST contain at most one `- component:` line per unique failing PURL (attributed to the first component carrying it)
- **FR-008**: On success, every duplicate component MUST receive the resolved external reference; BOM-level external reference deduplication MUST be preserved

**Breaker attribution**

- **FR-009**: Once the breaker is tripped, rejected resolutions MUST fail with the bare resolver-unavailable sentinel (`PURL resolver unavailable`) — without the endpoint and without the last infrastructure error, which belong to a different PURL
- **FR-010**: The per-image failure report MUST collapse all breaker-rejected failures into a single summary line: `    - PURL resolver unavailable: resolution skipped for <N> package URLs`, where N counts unique skipped PURLs
- **FR-011**: The terminal build error MUST keep the format `PURL resolver unavailable at <endpoint>: <last infrastructure error>` and appear exactly once per build (unchanged from spec 017)
- **FR-012**: Terminality detection (the build phase treating a resolver-unavailable failure as terminal via the sentinel) MUST survive both the bare-sentinel change and the summary-line grouping

**Preserved behavior**

- **FR-013**: Content failures (HTTP 4xx, empty URL in resolve response, unknown external reference kind, component without PURL) MUST keep their per-component lines and the deferred aggregation semantics of specs 011 and 017

### Go-Specific Requirements

- Sanitization of non-200 responses is a pure function (`statusErrorDetail(status, contentType string, body []byte) string`) unit-testable without HTTP
- The cancellation guard wraps both transport and body-read errors of a resolve attempt; the canceled-path error is `backoff.Permanent` so the retry loop stops immediately
- Unique-PURL resolution keeps the existing concurrency bound (errgroup, limit 10) inside one image's enrichment
- `ResolverBreaker.Allow` returns the bare `ErrResolverUnavailable` sentinel; `ResolverBreaker.UnavailableError` remains the only carrier of endpoint + last infrastructure error
- New and changed tests are mutation-verified (each guard removed in turn must fail its test)

### Key Entities

- **Status error detail** (`pkg/sbom/externalref/service.go`): rendering of a non-200 response into a single-line error — status line, optional sanitized body
- **Cancellation guard** (`pkg/sbom/externalref/service.go`): classification path for infrastructure errors that substitutes the plain context error when the request context is canceled and bypasses breaker accounting
- **PURL outcome** (`pkg/sbom/externalref/enricher.go`): the shared result (external reference or error) of resolving one unique PURL, fanned out to all duplicate components
- **Component failure report** (`pkg/sbom/externalref/enricher.go`): per-image detail lines; one line per unique failing PURL, one summary line for all breaker-rejected PURLs
- **ResolverBreaker** (`pkg/sbom/externalref/breaker.go`): unchanged latching semantics; `Allow` yields the bare sentinel, `UnavailableError` the full terminal text

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: A resolver outage behind a proxy (5xx with HTML pages) produces an SBOM failure section bounded by: one line per unique real failure per image + one summary line per image + one terminal error — on the motivating CI job this collapses ~2300 lines to under ~20
- **SC-002**: No HTML fragment appears in build output regardless of what the resolver or its proxy returns — verified by unit tests (HTML body, HTML content type, sanitizer table) and mutation runs
- **SC-003**: When one image's converge fails terminally, no sibling image's warning contains the failed image's report — verified by a unit test injecting a cancellation cause and asserting it does not leak into the resolve error
- **SC-004**: For a BOM with a PURL duplicated N times, the resolver receives exactly 1 request and the failure report names the PURL exactly once — verified by counting unit tests
- **SC-005**: After the breaker trips, the report contains zero per-component endpoint/last-error annotations and exactly one skip-summary line — verified by unit tests
- **SC-006**: The terminal error names the endpoint and the last real infrastructure error exactly once per build — preserved behavior, guarded by existing spec 017 tests (`tracker_test.go` single-occurrence assertion)
- **SC-007**: No regression in the e2e mixed-failure scenario — `task test:e2e paths="./test/e2e/sbom" labelFilter="purl-resolver-errors"` passes (per-component 404 lines still rendered, `image-ok` unaffected)

## Assumptions

- The resolver endpoint and its proxy are external and may return arbitrary bodies; werf controls only how it reports them
- 200 characters of a single-line body is enough context for a resolver-side JSON error; longer bodies add noise, not signal
- Attributing a shared-PURL failure to the first component carrying it is acceptable: duplicate components in a merged BOM name the same package
- Cross-image resolve caching (one request per PURL per *build* instead of per image) is a possible future optimization, out of scope here
- Specs `011-batch-purl-resolver-errors` and `017-sbom-converge-failure-semantics` remain authoritative for aggregation and failure-class semantics; this spec only changes how individual failures are *rendered* and how duplicate/canceled resolutions are *counted*
