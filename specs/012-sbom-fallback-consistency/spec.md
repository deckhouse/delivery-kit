# Feature Specification: Fix SBOM Fallback Annotation Loss

**Feature Branch**: `012-sbom-fallback-consistency`

**Created**: 2026-07-29

**Status**: Draft

**Input**: User description: "Исправление потери аннотаций при конкурентной записи fallback-индекса SBOM"

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

### User Story 1 — Concurrent SBOM pushes retain all annotations (Priority: P1)

When building a multi-image project (e.g., `frontend` + `backend`), each image pushes its SBOM artifact to the shared fallback index. Previously, the second push could overwrite the first push's annotation (annotation loss). With the fix, all image annotations survive regardless of push order or timing.

**Why this priority**: Annotation loss means the user's SBOM metadata is silently corrupted, requiring a full rebuild to recover. This is a correctness bug affecting every multi-image project.

**Independent Test**: Can be tested by pushing SBOM artifacts for two images nearly simultaneously and then verifying that both annotations are present in the fallback index.

**Acceptance Scenarios**:

1. **Given** a multi-image project with images `A` and `B`, **When** SBOM artifacts are pushed concurrently for both images, **Then** the fallback index contains annotations for both `A` and `B`.
2. **Given** a fallback index that already contains annotation for image `A`, **When** an SBOM artifact for image `B` is pushed, **Then** the index retains the annotation for `A` and also contains the new annotation for `B`.
3. **Given** three or more images pushing SBOMs to the same parent digest, **When** all push concurrently, **Then** all annotations are present in the final index.

---

### User Story 2 — The system recovers gracefully from registry staleness (Priority: P2)

Even after a successful write, the registry may serve stale data for a short period (eventual consistency). The fix must ensure that a subsequent read-after-write returns the up-to-date index before declaring success.

**Why this priority**: Without read-after-write verification, the system cannot distinguish between a successful committed write and a stale read that appears to have succeeded.

**Independent Test**: Can be tested by verifying that after a push, repeated reads of the fallback tag eventually return the correct digest.

**Acceptance Scenarios**:

1. **Given** a fallback index was just written, **When** the system reads it back, **Then** the digest of the read matches the digest of what was written.
2. **Given** the registry returns stale data after a write, **When** the system retries with backoff, **Then** it eventually reads the correct data.
3. **Given** the registry never converges within the timeout, **When** the retry budget is exhausted, **Then** the push fails with a clear error message.

---

### User Story 3 — Existing SBOM retrieval continues to work unchanged (Priority: P3)

Users who only build single-image projects or who read SBOMs (not write them) must see no behavioral or performance changes.

**Why this priority**: The fix must not regress the read path, which is used by downstream consumers (e.g., vulnerability scanners).

**Independent Test**: Can be tested by reading SBOM annotations from a fallback index before and after the fix — results must be identical.

**Acceptance Scenarios**:

1. **Given** a fallback index with known annotations, **When** `GetAttached` is called, **Then** it returns the same results as before the fix.
2. **Given** a fallback index does not exist (empty), **When** `GetAttached` is called, **Then** it returns `(empty, false)` with no error.

---

### Edge Cases

- What happens when the registry returns a non-404 error on the initial read? The operation must fail with a descriptive error, not silently fall back to an empty index.
- How does the system handle a tag that has been deleted externally between reading and writing? The push will succeed (creating a new index), which is acceptable.
- What happens if the parent digest is invalid or malformed? The tag generation must fail with a clear error.
- How does the system behave under network partitions? After the backoff timeout is exhausted, the push fails, and the caller receives an error.

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: The system MUST serialize concurrent writes to the same fallback tag within a single process so that no writes are lost.
- **FR-002**: After writing a fallback index, the system MUST verify that reading back the index returns the same content (digest match) before declaring success.
- **FR-003**: If digest verification fails (stale read), the system MUST retry with exponential backoff and a bounded maximum retry budget.
- **FR-004**: If the retry budget is exhausted without successful verification, the system MUST return an error to the caller and MUST NOT silently drop annotations.
- **FR-005**: The system MUST NOT change the behavior or performance of the read path (`GetAttached`) — it must return the same results as before the fix for both existing and non-existing indices.
- **FR-006**: The system MUST guarantee that a single-image SBOM push (no concurrency) continues to succeed with the same semantics as before.

### Key Entities

- **Fallback Index**: An OCI image index stored under a mutable tag (`sha256-<parentDigest>`). Contains a list of artifact descriptors, each carrying annotations (e.g., `io.werf.image-name`).
- **Artifact Descriptor**: A reference to an individual SBOM artifact (media type, digest, size, annotations, artifact type).
- **Tag Mutex Key**: A string key derived from the repository and parent digest, used to serialize writes to the same fallback tag within a single process.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: Zero annotation loss in a three-image concurrent push scenario, verified by automated race-condition tests.
- **SC-002**: Read-after-write verification completes within 30 seconds under normal registry latency (p99).
- **SC-003**: No regressions in existing SBOM retrieval tests — all current `GetAttached` pass/fail scenarios produce identical results.
- **SC-004**: The fix introduces no measurable performance degradation (<5% overhead) for single-image SBOM pushes compared to the pre-fix baseline.

## Assumptions

- The container registry enforces at-least-once writes: once `WriteIndex` succeeds, the written data is eventually persisted, but reads may return stale data for a bounded window.
- The fix targets in-process concurrency (multiple goroutines pushing SBOMs for different images). Cross-process concurrency (multiple werf processes) is left for a future iteration — the per-tag mutex only serializes within a single process.
- The maximum registry convergence time is assumed to be under 30 seconds under normal operating conditions. Unusually slow registries may hit the retry timeout and fail the push.
- Existing CAS-based retry logic (`maxRetries = 3`) will be replaced by the mutex + digest-verification approach.