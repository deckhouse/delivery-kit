# Feature Specification: Fallback Index Annotation Loss

**Feature Branch**: `test/sbom/cover-manifest-annotations`

**Created**: 2026-07-23

**Status**: migrated

**Input**: Reverse-engineered from existing code in `pkg/oci/artifact/`, `pkg/sbom/`, and `test/e2e/sbom/`

## Project Context

**Delivery Kit** is a Go CLI tool for full-cycle CI/CD to Kubernetes. It is built on top of werf with Deckhouse Platform extensions. Key subsystems:

- **Build** (`pkg/build/`) — Container image building via Buildah
- **Deploy** (`pkg/deploy/`) — Kubernetes deployment via werf/nelm (Helm-based)
- **SBOM** (`pkg/sbom/`) — Software Bill of Materials generation and validation
- **Cleanup** (`pkg/cleaning/`) — Container registry cleanup policies
- **Signature** (`pkg/signature/`) — Container image signing and verification
- **Docker Registry** (`pkg/docker_registry/`) — OCI registry operations
- **Config** (`pkg/config/`) — werf.yaml configuration parsing

The SBOM subsystem includes an `oci/artifact` package that manages OCI artifacts (SBOMs, attestations) attached to container images. When multiple images share the same parent digest, artifact entries are stored in a shared fallback index tag and distinguished by annotations on OCI Image Index manifest descriptors.

## User Scenarios & Testing *(mandatory)*

### User Story 1 — Fallback index annotation preservation for multi-image builds (Priority: P1)

When two images (`frontend`, `backend`) share the same parent digest, their SBOM entries are stored in a shared fallback index tag. The fallback index mechanism must preserve the `io.werf.image-name` annotation on each entry so that different images' artifacts can be distinguished. A regression test verifies this: it builds both images, pulls the fallback index directly via `go-containerregistry`, and asserts that annotations for both `frontend` and `backend` are present.

**Fixture isolation**: The regression test `manifest annotation preservation` uses a dedicated fixture at `test/e2e/sbom/_fixtures/regressions/manifest_annotation/` that is structurally independent from the `lifecycle/multi_image` fixture used by `lifecycle_test.go`. This isolation prevents CI interference — if the regression test shared the `multi_image` fixture, concurrent test execution could lead to fallback index tag collisions and false-positive failures on either side.

## Requirements *(mandatory)*

### Functional Requirements

| ID | Requirement | Priority | Source |
|----|-------------|----------|--------|
| F1 | Fallback index tag must support multiple entries for different images sharing the same parent digest | P1 | `pkg/oci/artifact/fallback.go:updateFallbackIndex` |
| F2 | Each fallback index entry must be annotated with `io.werf.image-name` to identify which image it belongs to | P1 | `pkg/oci/artifact/store.go:Attach` |
| F3 | `GetAttached` must return the correct artifact descriptor for a given (parentDigest, artifactType, imageName) tuple | P1 | `pkg/oci/artifact/fallback.go:GetAttached` |
| F4 | `updateFallbackIndex` must replace existing entries with the same artifactType and imageName instead of accumulating duplicates | P1 | `pkg/oci/artifact/fallback.go:updateFallbackIndex` |
| F5 | Regression test fixture must be fully isolated from the `lifecycle/multi_image` fixture: unique `werf.yaml`, `Dockerfile.builder-base`, `werf-giterminism.yaml`, and project name — no shared directories or files | P1 | `test/e2e/sbom/_fixtures/regressions/manifest_annotation/` |

### Non-Functional Requirements

| ID | Requirement | Priority |
|----|-------------|----------|
| NF1 | The fallback index mechanism must work with the Docker Distribution registry | P1 |
| NF2 | The fix must not depend on annotations on OCI Image Index descriptors for distinguishing image entries | P1 |

## Success Criteria *(mandatory)*

| ID | Criterion | Verified By |
|----|-----------|-------------|
| SC1 | Regression test `manifest annotation preservation` passes without interfering with `lifecycle/multi_image` tests | `test/e2e/sbom/regressions_test.go` |

## Assumptions *(mandatory)*

| ID | Assumption | Rationale |
|----|------------|-----------|
| A1 | The Docker Distribution registry does not reliably preserve the `annotations` field on descriptors within OCI Image Index manifests across write/read cycles | Inferred from diagnostic evidence: size mismatches, manifest accumulation, and failed retries |
| A2 | Two images sharing the same parent digest (same packages stage) will be built concurrently and push to the same fallback index tag | Inferred from the multi-image build scenario |
| A3 | Annotations on OCI manifest descriptors are the only mechanism currently used to distinguish between different images' entries in the fallback index | Code analysis of `updateFallbackIndex` and `GetAttached` |
| A4 | The regression test fixture must not share `Dockerfile.builder-base` content, project name, or image names with the `lifecycle/multi_image` fixture to avoid fallback index tag collisions and CI interference when both test suites run concurrently | Inferred from CI failures: structurally identical `Dockerfile.builder-base` and overlapping image name patterns caused false-positive failures |

## Known Issues

| ID | Issue | Status |
|----|-------|--------|
| K1 | `updateFallbackIndex` reads `manifest.Annotations[io.werf.image-name]` to match existing entries, but the registry drops annotations on write-back, causing entries to accumulate instead of being replaced | Open — root cause identified, fix not yet implemented |
| K2 | The `GetAttached` function cannot find the correct entry when annotations are missing, causing `werf sbom merge` to fail with "artifact not found" | Open — consequence of K1 |