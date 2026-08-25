# Feature Specification: Unify os-pm SBOM Merging

**Feature Branch**: `019-unify-os-pm-merge`

**Created**: 2026-08-25

**Status**: Draft

**Input**: User description: "Unify os_pm BOM merging into cyclonedxutil merge: CollectAndMergeBOM must delegate to the shared MergeBOMs pipeline instead of manually appending Components/Dependencies"

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

### User Story 1 - Consistent SBOM merging for pm packages (Priority: P1)

As an image maintainer who builds images with the pm package manager enabled, I want the pm-collected package list to be merged into the image SBOM through the same merge pipeline as base-image and imported SBOMs, so that the final SBOM is uniformly validated, deduplicated, and internally consistent regardless of which source contributed the data.

**Why this priority**: This is the core of the feature. Today the pm-package merge is a hand-rolled shortcut that merges only two document sections and skips validation and reference-uniqueness guarantees applied to every other merge in the product. Any divergence between the two merge paths is a latent correctness bug in a compliance-critical artifact.

**Independent Test**: Build an image with pm packages enabled on top of a base image that already has an SBOM; verify that the resulting SBOM contains the pm packages, retains the image metadata, passes CycloneDX schema validation, and contains no duplicate document references.

**Acceptance Scenarios**:

1. **Given** an image SBOM produced by the scanner and a non-empty pm package index in the image, **When** SBOM processing completes, **Then** the final SBOM contains both the scanner-discovered components and the pm packages, with the image's own metadata preserved.
2. **Given** a pm package index that yields packages, **When** the pm data is merged, **Then** every component in the final SBOM has a document-unique reference (no reference collisions between pm entries and other sources).
3. **Given** an empty or absent pm package index, **When** SBOM processing completes, **Then** the final SBOM is exactly what the other sources produced, unchanged.
4. **Given** a pm-contributed document declared under an unsupported SBOM specification version, **When** the merge runs, **Then** the merge fails with a clear error instead of silently producing a partially merged document.

---

### User Story 2 - Future-proof pm data propagation (Priority: P2)

As a maintainer of the SBOM subsystem, I want the pm merge to carry over every section of the pm-contributed document (not a hardcoded subset), so that when pm data starts including additional sections (e.g. properties, annotations), they appear in the final SBOM without further code changes.

**Why this priority**: The current shortcut silently drops any section other than components and dependencies. This is an invisible data-loss trap for future pm enrichment work.

**Independent Test**: Construct a pm-contributed document containing a section beyond components/dependencies and verify the section survives into the merged output.

**Acceptance Scenarios**:

1. **Given** a pm-contributed document with sections beyond components and dependencies, **When** the merge runs, **Then** those sections are present in the final SBOM.

---

### Edge Cases

- pm index present but yields zero packages → merge is skipped entirely; the incoming SBOM is returned as-is.
- No incoming SBOM exists (pm is the only source) → a fresh valid SBOM document is created and the pm packages merged into it.
- Duplicate packages between the scanner output and pm output (same normalized package identity) → exactly one component survives deduplication.
- pm document reference identifiers colliding with identifiers already present in the incoming SBOM → references are rewritten to remain document-unique, and all internal links follow the rewrite.

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: The pm package merge MUST go through the same shared SBOM merge pipeline used for base-image and imported SBOMs, with no separate hand-rolled merge logic.
- **FR-002**: The merge MUST preserve the incoming SBOM's metadata (the image's own identity) in the merged result.
- **FR-003**: The merge MUST validate the specification version of every participating document and fail with a descriptive error on unsupported versions.
- **FR-004**: The merged result MUST have document-unique component references, with all internal cross-references rewritten consistently.
- **FR-005**: The merged result MUST be deduplicated by normalized package identity, keeping a single component per identity.
- **FR-006**: All sections of the pm-contributed document MUST propagate into the merged result, not a fixed subset.
- **FR-007**: When the pm source yields no packages, the incoming SBOM MUST be returned unchanged.
- **FR-008**: When no incoming SBOM exists, the merge MUST produce a new valid SBOM document containing the pm packages.

### Key Entities

- **Image SBOM (target)**: The CycloneDX document representing the image being processed; carries the image's metadata; produced by the scanner or created empty.
- **pm-contributed document**: A CycloneDX document derived from the pm package index inside the image; lists installed packages and their dependency relations.
- **Merged SBOM**: The single final document combining all sources; validated, reference-unique, deduplicated; this is what gets signed and pushed.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: The final SBOM of a pm-enabled image passes CycloneDX schema validation, including the uniqueness constraints on components and references.
- **SC-002**: For an image with both scanner-discovered and pm-provided packages, 100% of packages from both sources are present in the final SBOM (after identity-based deduplication).
- **SC-003**: The codebase contains exactly one SBOM merge implementation; the pm path introduces zero merge logic of its own.
- **SC-004**: A malformed or version-incompatible pm-contributed document is rejected with an actionable error message rather than producing a silently degraded SBOM.

## Assumptions

- Component identity for deduplication is the normalized package URL, as already established by the shared merge pipeline; scanner and pm packages use disjoint package-URL namespaces, so cross-source collisions are not expected in practice.
- The merged SBOM receiving a fresh document serial number (rather than retaining the incoming one) is acceptable, because SBOM caching keys are computed from inputs, not from the merged document.
- The precedence rule of the shared pipeline (earlier sources win on identity collision) is acceptable for pm data, consistent with how base and imported SBOMs already behave.
- The pm-contributed document is always produced under the supported CycloneDX specification version by the collector itself.
