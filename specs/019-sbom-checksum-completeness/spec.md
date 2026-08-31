# Feature Specification: SBOM Checksum Completeness

**Feature Branch**: `fix/sbom/checksum-completeness`

**Created**: 2026-08-24

**Status**: Draft

**Input**: User description: "SBOM artifact checksum must account for all generation inputs: GOST configuration and unambiguous checksum part encoding."

## Project Context

**Delivery Kit** is a Go CLI tool for full-cycle CI/CD to Kubernetes. It is built on top of werf with Deckhouse Platform extensions. Key subsystems:

- **Build** (`pkg/build/`) — Container image building via Buildah
- **Deploy** (`pkg/deploy/`) — Kubernetes deployment via werf/nelm (Helm-based)
- **SBOM** (`pkg/sbom/`) — Software Bill of Materials generation and validation
- **Cleanup** (`pkg/cleaning/`) — Container registry cleanup policies
- **Signature** (`pkg/signature/`) — Container image signing and verification
- **Docker Registry** (`pkg/docker_registry/`) — OCI registry operations
- **Config** (`pkg/config/`) — werf.yaml configuration parsing

## Problem Statement

Each built image gets an SBOM artifact attached in the registry. Before regenerating an SBOM, the build reuses a previously attached artifact when its recorded checksum matches the checksum computed for the current build settings. The checksum's contract: given the same parent image (identified by its digest), reuse is safe only if regeneration would produce the same SBOM.

Today the checksum omits generation inputs, so users who change those inputs keep receiving a stale SBOM:

1. **GOST configuration**: GOST properties are applied to the final SBOM as a post-processing step, but the GOST configuration feeds no stage digest and is reflected in the checksum only indirectly (through base/import documents it happens to modify) — and not at all when there are no base/import documents. Changing or adding GOST settings leaves a cached SBOM without the expected GOST properties.
2. **Ambiguous encoding**: checksum parts are concatenated with a plain separator, so different combinations of empty and non-empty parts can collide, producing an identical checksum for different settings (e.g. a signer identity containing the separator absorbs the platform slot boundary).

The `packages` directive (os-pm) was initially suspected as a third gap but is covered by the parent stage digest: the directive's package list feeds the Packages stage digest through the generated install command, and the stage itself appears/disappears with the directive, so any toggle changes the parent digest and misses the SBOM cache without the checksum's help.

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Changing GOST configuration regenerates the SBOM (Priority: P1)

A user builds an image, then adds or changes GOST settings (attack surface / security function) in werf.yaml. The next build must produce an SBOM carrying the new GOST properties, including for images that have no base or imported SBOM documents.

**Why this priority**: GOST properties exist for compliance; a cached SBOM without them fails the user's compliance requirement silently.

**Independent Test**: Build an image without GOST config, then add GOST config and rebuild; verify the SBOM was regenerated and carries GOST properties.

**Acceptance Scenarios**:

1. **Given** an image with a cached SBOM and no GOST configuration, **When** the user adds GOST configuration and rebuilds, **Then** a new SBOM is generated with GOST properties applied.
2. **Given** an image with a cached SBOM generated with GOST configuration, **When** the user changes a GOST setting and rebuilds, **Then** a new SBOM is generated.
3. **Given** an image whose SBOM inputs include no base or imported documents (e.g. built from scratch), **When** GOST configuration changes, **Then** the SBOM is still regenerated.

---

### User Story 2 - Distinct settings never share a checksum (Priority: P2)

Any two distinct combinations of SBOM generation settings must map to distinct checksums, including combinations that differ only in which optional settings are empty.

**Why this priority**: Encoding ambiguity is a latent correctness hazard rather than a currently observed bug; fixing it alongside the other changes avoids a second cache-invalidation wave later.

**Independent Test**: Verify at the unit level that changing any single generation input changes the checksum, and that empty/absent optional inputs cannot collide with shifted part combinations.

**Acceptance Scenarios**:

1. **Given** two builds that differ in exactly one generation input, **When** checksums are computed, **Then** the checksums differ.
2. **Given** the same generation inputs, **When** checksums are computed repeatedly, **Then** the checksum is identical (stable).

---

### Edge Cases

- Existing users upgrading: every image's first rebuild after upgrade regenerates its SBOM once (checksum format changed). Subsequent rebuilds reuse the cache as before. This is an accepted, one-time cost and must happen in a single wave (all fixes shipped together).
- Signed SBOMs: signer identity remains part of the checksum; signing behavior is unchanged.
- Multi-platform builds: the target platform stays a checksum input, but it is now always present as a part instead of being appended only when non-empty. Single-platform checksums therefore change once, which is part of the same one-time regeneration wave.

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: The SBOM artifact checksum MUST incorporate the effective GOST configuration, including when the SBOM has no base or imported documents.
- **FR-002**: The GOST configuration MUST be reflected in the checksum through exactly one explicit channel (not solely via side effects on base/import documents).
- **FR-003**: Checksum part encoding MUST be unambiguous: fixed arity (every part always present, empty string when unset), keyed parts, no conditionally omitted parts, and a part separator whose absorption by a part value cannot produce an identical checksum input — so no two distinct part sequences collide.
- **FR-004**: An unchanged configuration MUST keep producing the same checksum across repeated builds of the same parent image (cache reuse preserved).
- **FR-005**: All checksum format changes MUST ship together so existing users experience at most one SBOM regeneration wave.
- **FR-006**: The checksum contract and its intentional exclusions (external reference enrichment data; go-module patcher inputs, the scratch-base mode and the os-pm packages directive, covered transitively by the parent image digest; generator logic changes, covered by the artifact format version) MUST be documented at the checksum computation site.

### Key Entities

- **SBOM artifact checksum**: A stable identifier recorded as an annotation on the attached SBOM artifact; encodes all generation inputs other than the parent image content.
- **Parent image digest**: The registry digest of the image stage the SBOM describes; covers everything inside the image filesystem.
- **Generation inputs**: Scanner settings (image, catalogers, output standard), base/import SBOM documents, GOST configuration, signer identity, target platform, artifact format version.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: After any GOST configuration change, 100% of rebuilds produce a freshly generated SBOM, including for images without base/import documents.
- **SC-002**: With unchanged configuration, rebuilds reuse the cached SBOM (no regeneration observed).
- **SC-003**: Changing any single generation input changes the checksum; identical inputs always give an identical checksum (verified exhaustively at the unit level).
- **SC-004**: Existing users experience exactly one SBOM regeneration wave after upgrading.

## Assumptions

- The parent image digest fully covers image filesystem content (packages, lock files, pm metadata); the checksum only needs to cover inputs outside the image.
- Go-module patcher inputs are covered transitively by the parent image digest (build context changes invalidate the stage); they are intentionally out of scope. Patcher logic changes are covered by the artifact format version bump discipline.
- The scratch-base mode (`from: scratch`) is covered transitively by the parent image digest: changing the base image changes the digest of every stage, so the mode flag needs no explicit checksum part.
- The os-pm `packages` directive is covered transitively by the parent image digest: the package list feeds the Packages stage digest through the generated install command, and the stage appears/disappears with the directive (confirmed by specs/018-packages-stage-invalidation and pkg/build/stage/packages.go).
- External reference enrichment depends on external registries and is intentionally excluded from the checksum (non-deterministic input).
- A one-time SBOM regeneration wave on upgrade is acceptable; it matches the established artifact format version bump mechanism.
- Stage-digest invalidation for the `packages` directive (specs/018-packages-stage-invalidation) is a separate concern; this feature fixes the SBOM artifact checksum layer independently.
