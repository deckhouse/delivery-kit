# Feature Specification: SBOM Artifact Storage Model

**Feature Branch**: `refactor/sbom/artifact-storage-format`

**Created**: 2026-08-06

**Status**: migrated

**Input**: Reverse-engineered from existing code in `pkg/oci/artifact/` (PR #222)

## Project Context

**Delivery Kit** is a Go CLI tool for full-cycle CI/CD to Kubernetes. It is built on top of werf with Deckhouse Platform extensions. Key subsystems:

- **Build** (`pkg/build/`) — Container image building via Buildah
- **Deploy** (`pkg/deploy/`) — Kubernetes deployment via werf/nelm (Helm-based)
- **SBOM** (`pkg/sbom/`) — Software Bill of Materials generation and validation
- **Cleanup** (`pkg/cleaning/`) — Container registry cleanup policies
- **Signature** (`pkg/signature/`) — Container image signing and verification
- **Docker Registry** (`pkg/docker_registry/`) — OCI registry operations
- **Config** (`pkg/config/`) — werf.yaml configuration parsing

The `pkg/oci/artifact` package stores OCI artifacts (SBOMs, attestations) attached to container images. Artifacts of a parent digest are listed in an OCI image index published under the canonical referrers tag `sha256-<hex>` of that digest, per the [OCI referrers tag schema](https://github.com/opencontainers/distribution-spec/blob/main/spec.md#referrers-tag-schema). Every image resolving to the same digest shares that index, and go-containerregistry maintains the same index on its own for any pushed manifest carrying a `subject`.

## Supersedes

- **`specs/010-sbom-fallback-annotation-loss`** — described the symptom: index descriptors without `io.werf.image-name`. The root cause is not annotation loss by a registry but a second writer: go-containerregistry appends its own descriptor for the same manifest, without werf annotations, on every artifact push. This feature removes those duplicates by matching descriptors by manifest digest.
- **`specs/012-sbom-fallback-consistency`** — described the lost update between concurrent writers of the shared index. The CAS-style check it introduced (index must be byte-identical to what was pushed) failed on any legitimate concurrent write and on stale reads. This feature replaces it with a convergent write.

## User Scenarios & Testing *(mandatory)*

### User Story 1 — Concurrent SBOM attach for images sharing a digest (Priority: P1)

Two werf images with identical content resolve to one parent digest and attach their SBOMs concurrently, from one or several processes. Both attaches succeed, and the index ends up containing both entries: a writer that observes its entry missing republishes it, merging with whatever is currently in the index, until the entry is observed.

**Covered by**: `attach_integration_test.go` — "should retain all annotations under concurrent push", "should restore its entry after another writer replaced the whole index".

### User Story 2 — Reading a named or unnamed artifact (Priority: P1)

A consumer (`werf sbom get`, `werf attest get/ls/verify`, build SBOM cache) reads the artifact of a specific image by `(artifactType, imageName)`, or of any image when no name is given. Exactly one descriptor per artifact is returned: entries written by go-containerregistry for the same manifest are collapsed into the werf-annotated one.

**Covered by**: `attach_integration_test.go` — "should not leave a duplicate entry written by go-containerregistry", "should attach without an image name next to a named artifact"; `fallback_internal_test.go` — `matchDescriptors` and `isAttached` specs.

### User Story 3 — Discovery through the Referrers API after a registry upgrade (Priority: P2)

Once a registry that supports the OCI Referrers API is deployed, artifacts pushed by werf are discoverable through `GET /v2/<repo>/referrers/<digest>` without any change to the storage format: the artifact manifest itself carries the artifact type (via config media type) and the werf annotations, which is what a registry builds referrers descriptors from.

**Covered by**: `referrers_compat_test.go` — all specs run against a referrers-capable registry.

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: The artifact index of a parent digest MUST be published under the canonical referrers tag `sha256-<hex>` of that digest.
- **FR-002**: The artifact manifest MUST carry the werf annotations (`io.werf.image-name`, `io.werf.checksum`, `io.werf.target-platform`, each when non-empty) and MUST declare the artifact type through its config media type.
- **FR-003**: The artifact manifest MUST carry a `subject` reference to the parent image manifest.
- **FR-004**: An attach MUST NOT be reported successful until the index observably resolves the artifact key `(artifactType, imageName)` to the descriptor being attached, and to nothing else.
- **FR-005**: Every index write MUST merge the descriptor being attached into the index state that was read, never replace the index with locally constructed state alone.
- **FR-006**: Writers MUST match the artifact key exactly, an empty image name included; readers MUST treat an empty image name as matching any image.
- **FR-007**: Index entries sharing a manifest digest MUST be collapsed to one, preferring the werf-annotated descriptor, both on write (eviction) and on read (deduplication).
- **FR-008**: The artifact push and the index update MUST be serialized within a process per `(repo, parentDigest)`, covering the index write go-containerregistry performs on its own during the push.
- **FR-009**: An attach that cannot converge within its retry budget MUST fail with an explicit error naming the artifact type and parent digest.
- **FR-010**: Index updates MUST NOT be performed by any code path outside the tag lock (`Attach` is unexported as `attachDescriptor`).
- **FR-011**: Reading an absent index (HTTP 404) MUST be treated as an empty index, not an error.

### Non-Functional Requirements

- **NFR-001**: A single uncontended attach converges on the first round — no backoff sleeps on the happy path.
- **NFR-002**: The convergence retry budget is 30 seconds with exponential backoff starting at 500ms.
- **NFR-003**: Distinct artifacts always differ in manifest bytes (the image name is part of the manifest), so a manifest digest is a sound identity for deduplication.

## Success Criteria *(mandatory)*

- **SC-001**: Concurrent attaches of images sharing a parent digest all succeed and all entries are present afterwards.
- **SC-002**: A writer whose entry was dropped by a stale read or an overwrite restores it on a subsequent attach without losing other writers' entries.
- **SC-003**: The index contains exactly one entry per artifact; entries written by go-containerregistry for the same manifest are not visible to readers.
- **SC-004**: An artifact attached without an image name coexists with named artifacts and is replaced, not accumulated, on reattach.
- **SC-005**: Artifacts identical in payload but published under different image names produce distinct manifests and distinct index entries.
- **SC-006**: On a referrers-capable registry the artifact is listed by the Referrers API with the correct artifact type, while the tag-based index keeps working unchanged.
- **SC-007**: `task test:unit paths="./pkg/oci/..."` passes: 62 specs, including convergence-after-lost-update and unnamed-artifact scenarios.

## Assumptions *(mandatory)*

- **A-001**: Registries provide neither atomic index updates nor read-after-write guarantees; lost updates are therefore repaired (by republishing until observed), not prevented.
- **A-002**: go-containerregistry cannot be prevented from writing the referrers tag while manifests carry a `subject` and the registry lacks the Referrers API; its entries are tolerated and collapsed by digest instead. (`remote.WithReferrersTagFallback(false)` was evaluated and rejected: it makes the Referrers API mandatory and fails the push entirely on registries without it.)
- **A-003**: Convergence is probabilistic, not guaranteed: writers in sustained lockstep may need several rounds. Exponential backoff separates them in practice; the budget bounds the wait.
- **A-004**: The in-process tag mutex covers the common concurrency case (goroutines of one build). Across processes and hosts only convergence applies.
- **A-005**: Parent digests use sha256, matching the `sha256-` tag prefix.
