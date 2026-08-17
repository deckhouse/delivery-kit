# Feature Specification: SBOM Converge Failure Semantics

**Feature Branch**: `017-sbom-converge-failure-semantics`

**Created**: 2026-08-17

**Status**: Draft

**Input**: User description: "Fix SBOM converge failure handling: classify PURL resolution failures into content vs infrastructure, add a process-wide circuit breaker for an unavailable resolver, skip dependent images whose base failed enrichment with the real cause instead of a misleading error, guarantee the aggregated PURL report on every exit path, and fix the surrounding logging gaps. Input problem statement: PROBLEM.md (operator-helm build failure on werf 2.77.0-dk.2, discovered 2026-08-12)."

## Project Context

**Delivery Kit** is a Go CLI tool for full-cycle CI/CD to Kubernetes. It is built on top of werf with Deckhouse Platform extensions. Key subsystems:

- **Build** (`pkg/build/`) — Container image building via Buildah
- **Deploy** (`pkg/deploy/`) — Kubernetes deployment via werf/nelm (Helm-based)
- **SBOM** (`pkg/sbom/`) — Software Bill of Materials generation and validation
- **Cleanup** (`pkg/cleaning/`) — Container registry cleanup policies
- **Signature** (`pkg/signature/`) — Container image signing and verification
- **Docker Registry** (`pkg/docker_registry/`) — OCI registry operations
- **Config** (`pkg/config/`) — werf.yaml configuration parsing

## Background

SBOM converge processes images set by set, respecting `fromImage` dependency order. When external-reference (PURL) enrichment fails for an image, the failure is deferred (accumulated for one aggregated report at the end) so a single flaky package resolve does not kill a long build. This deferral has two unintended consequences observed in production (see [PROBLEM.md](./PROBLEM.md)):

1. The SBOM of the failed image is never published, so a dependent image in a later set hard-fails with a **wrong cause** ("rebuild the base with SBOM generation enabled" — the base *was* built with SBOM enabled in this very run), and this hard failure **aborts the build before the aggregated report is printed**. The aggregation contract only holds for leaf images.
2. When the resolver service itself is down (timeouts, connection errors), every image still spends its full retry budget, multiplying tens of seconds of pointless waiting by the number of images before the build finally fails with N identical timeout errors.

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Dependent image failure reports the real cause (Priority: P1)

A CI user builds a project where image B is built `fromImage` A. PURL enrichment for A fails (e.g. one package resolve times out). Today the build aborts on B with "the base image must have an SBOM artifact attached; rebuild it with SBOM generation enabled", which is false and actionless, and the aggregated PURL report is lost. Instead, the user must see that B was skipped because A's SBOM was not generated, with A's actual enrichment error, and the full aggregated report must still be printed.

**Why this priority**: This is the observed production failure. The wrong message sends operators down a dead-end path (SBOM *was* enabled), and losing the aggregated report hides the actual errors they need to act on.

**Independent Test**: Build a two-image project (B `fromImage` A) with a PURL resolver that fails resolution for a package of A. Verify the build output: no "rebuild with SBOM generation enabled" advice, B is reported as skipped with A's enrichment error as the cause, and the aggregated report lists A's component errors.

**Acceptance Scenarios**:

1. **Given** image B depends on image A and A's PURL enrichment failed in this run, **When** SBOM converge reaches B, **Then** B is not processed, and the final report states B was skipped because A's SBOM was not generated, including A's enrichment error.
2. **Given** any image failed PURL enrichment during converge, **When** the converge finishes (on any exit path, including a hard non-PURL error), **Then** the aggregated PURL report is printed.
3. **Given** image B references a base image that genuinely has no SBOM artifact and that base was NOT processed by this run, **When** SBOM converge reaches B, **Then** the existing "rebuild it with SBOM generation enabled" advice is still shown (it is correct in that case).

---

### User Story 2 - Unavailable resolver fails fast (Priority: P2)

A CI user builds a 14-image project while the external PURL resolver service is down. Today each image independently burns its full retry budget against the dead service, adding minutes of wall-clock time, and the build ends with 14 identical timeout errors. Instead, after a small number of consecutive infrastructure-level failures the build must conclude the resolver is unavailable, stop retrying for the remaining images, and fail promptly with one clear "resolver unavailable" error plus whatever was accumulated so far.

**Why this priority**: Wasted CI minutes on every build during a resolver outage, multiplied across all projects. Secondary to P1 because the build does eventually fail with a truthful (if repetitive) error.

**Independent Test**: Point the resolver at an unreachable address, build a multi-image project, and measure: the build fails after the circuit-breaker threshold instead of after (retry budget × image count), and the error names the resolver and its address once.

**Acceptance Scenarios**:

1. **Given** the resolver endpoint produces only infrastructure-level failures (timeout, connection refused, HTTP 5xx), **When** the number of consecutive such failures reaches the threshold, **Then** no further resolution attempts or retries are made for any remaining image, and the build fails with a single resolver-unavailable error naming the endpoint and the last underlying error.
2. **Given** the circuit breaker has tripped, **When** the build fails, **Then** the aggregated report of failures accumulated before the trip is still printed.
3. **Given** resolution failures are content-level (e.g. a package genuinely unknown to the resolver, HTTP 404), **When** many such failures occur across images, **Then** the circuit breaker does NOT trip and the existing aggregation behavior is preserved.
4. **Given** a mix of failures where an infrastructure failure streak is interrupted by a successful resolve, **When** converge continues, **Then** the consecutive-failure counter resets and the build proceeds normally.

---

### User Story 3 - SBOM log output names causes and targets (Priority: P3)

A user reading the build log of a failed or slow SBOM converge must be able to answer "what failed and why, where did time go, and which repo was touched" from the log alone. Today: an image block ends with `FAILED` and no cause next to it; the GOST experimental warning repeats once per image (14× per build); the "multiple artifact entries" warning floats between image blocks without naming the affected image; the "Copy SBOM artifacts into the final repo" message does not name the repo; PURL retry time is invisible inside the image block timer.

**Why this priority**: Quality-of-life for diagnosis; no functional behavior change. Valuable but strictly less urgent than P1/P2.

**Independent Test**: Run a build with a failing PURL resolve, GOST integration enabled, and a final repo configured; inspect the log for each of the five improvements.

**Acceptance Scenarios**:

1. **Given** an image's SBOM processing fails with a deferred (aggregated) error, **When** the image's log block closes with FAILED, **Then** the error text is printed inside that image's log block.
2. **Given** GOST SBOM integration is enabled for N images, **When** the build runs, **Then** the "GOST SBOM integration is experimental" warning is printed exactly once per process.
3. **Given** an SBOM artifact lookup finds multiple artifact entries for a digest, **When** the warning is printed, **Then** it names the image whose lookup produced it, the image names carried by the entries, and which entry was selected.
4. **Given** SBOM artifacts are copied into the final repo (or cache repos), **When** the copy log message is printed, **Then** it includes the repo address.
5. **Given** external-reference resolution takes noticeable time (retries), **When** the image's SBOM is processed, **Then** the resolution runs inside its own named log section with a timer, so its duration is visible within the image block.

---

### Edge Cases

- Base image failed enrichment AND the resolver circuit breaker trips mid-run: dependents of the failed base are reported as skipped, the breaker error is the terminal error, and the accumulated report is still printed.
- An image whose base failed enrichment is itself a base for a third image (transitive chain A → B → C): C is skipped for the same root cause (A's enrichment error), not for a cause blaming B.
- Multiplatform image (several platform entries per image name): a single platform's enrichment failure marks the whole image name as failed for dependency purposes (its SBOM set is incomplete).
- Hard non-PURL error (e.g. registry push failure) occurs after some PURL errors were accumulated: both the hard error and the aggregated report must surface; the hard error remains the build's terminal error.
- The circuit-breaker threshold is reached exactly on the last remaining resolution attempt of the build: the build fails with the resolver-unavailable error; no behavioral difference from tripping earlier.
- Enrichment is disabled or no external references need resolution: nothing changes; no breaker, no new messages.

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: The system MUST classify each external-reference resolution failure as either *content* (the resolver answered authoritatively that the package is unknown/invalid, e.g. HTTP 404) or *infrastructure* (the resolver could not be reached or answered abnormally: timeout, connection error, HTTP 5xx).
- **FR-002**: Content failures MUST keep the existing behavior: deferred, accumulated, and reported once in the aggregated hierarchical report (per `wiki/pages/error-aggregation-strategy.md`).
- **FR-003**: The system MUST maintain a process-wide count of consecutive infrastructure failures across all images; a successful resolution resets it. When the count reaches a threshold, the resolver MUST be declared unavailable for the remainder of the build: no further resolution attempts or retries are performed.
- **FR-004**: When the resolver is declared unavailable, the build MUST fail with a single error naming the resolver endpoint and the last underlying infrastructure error, accompanied by the aggregated report of failures accumulated so far.
- **FR-005**: An image whose PURL enrichment failed (deferred) MUST be recorded as "SBOM not generated" for dependency purposes; its published SBOM set is treated as absent for this run.
- **FR-006**: Before processing an image whose base image is recorded as "SBOM not generated" in this run, the system MUST skip that image's SBOM converge and record it as skipped with the base image's actual enrichment error as the cause. Skipping propagates transitively.
- **FR-007**: Skipped images MUST appear in the aggregated report with their cause; they MUST NOT produce the "must have an SBOM artifact attached; rebuild it with SBOM generation enabled" error.
- **FR-008**: The "rebuild it with SBOM generation enabled" advice MUST be shown only when the base SBOM is absent AND the base image was not processed by the current run.
- **FR-009**: The aggregated PURL report MUST be printed on every exit path of SBOM converge — happy path, hard error, and circuit-breaker trip. If a hard error and accumulated PURL errors coexist, both MUST surface, with the hard error as the terminal error.
- **FR-010**: A deferred enrichment error MUST be printed inside the failing image's own log block before the block closes with FAILED.
- **FR-011**: The GOST experimental-integration warning MUST be printed at most once per process.
- **FR-012**: The "multiple artifact entries" warning MUST name the image whose lookup produced it, the image names carried by the found entries, and the selected entry.
- **FR-013**: Log messages about copying SBOM artifacts into final/cache repos MUST include the repo address.
- **FR-014**: External-reference resolution MUST run inside its own named log section with a timer, visible within the image's log block.
- **FR-015**: The circuit-breaker threshold MUST have a fixed built-in default; no new CLI flags or configuration options are introduced by this feature.

### Key Entities

- **Failure class**: content vs infrastructure — the property of a single resolution failure that decides aggregation vs breaker accounting.
- **Enrichment failure record**: per image name — the accumulated component-level errors of an image whose enrichment failed (existing aggregation entry, extended to serve as the skip cause for dependents).
- **Skip record**: per image name — marks an image whose converge was skipped, pointing at the root-cause image and its enrichment error.
- **Resolver availability state**: process-wide — consecutive infrastructure-failure counter and tripped/not-tripped state.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: In a dependent-image failure scenario, the build output contains the real cause (base enrichment error) and zero occurrences of the misleading "rebuild it with SBOM generation enabled" advice.
- **SC-002**: The aggregated PURL report is printed in 100% of converge failure scenarios (leaf failure, dependent failure, hard error, breaker trip) — verified by tests covering each exit path.
- **SC-003**: With an unreachable resolver and a 14-image project, total time spent on resolution attempts is bounded by the breaker threshold (independent of image count), reducing wasted wall-clock time versus today's per-image retry budget by at least 80% for builds of 5+ images.
- **SC-004**: A resolver outage produces exactly one resolver-unavailable error naming the endpoint, instead of N identical per-image timeout errors.
- **SC-005**: The GOST experimental warning appears exactly once in a build log regardless of image count.
- **SC-006**: For every image block that ends with FAILED, the log block contains the causing error text.

## Assumptions

- The circuit-breaker threshold default is small (single digits, e.g. 3–5 consecutive infrastructure failures); the exact value is an implementation decision guarded by tests, not user-configurable in this feature.
- HTTP 4xx responses other than timeout-like conditions are treated as content failures (the resolver answered authoritatively); 5xx, transport errors, and timeouts are infrastructure failures.
- "Consecutive" is counted across the whole process (all images, all workers), not per image, since the breaker models the health of the single shared resolver service.
- Retry policy per individual request (spec `011-reduce-purl-retries-duration`) is unchanged; the breaker sits above it and only decides whether further attempts happen at all.
- The aggregated report format defined in `wiki/pages/error-aggregation-strategy.md` is preserved; skipped images are added as a new kind of entry under the same hierarchical format.
- Multiplatform note: failure of any platform variant of an image name marks that image name as failed for dependency-skip purposes.
- The operational follow-ups from PROBLEM.md (resolver service health, syft picking a nuget package out of a golang builder image) are out of scope — they are not Delivery Kit changes.
