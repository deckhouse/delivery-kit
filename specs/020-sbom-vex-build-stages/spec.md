# Feature Specification: SBOM and VEX as Build Stages

**Feature Branch**: `020-sbom-vex-build-stages`

**Created**: 2026-09-01

**Status**: Draft

**Input**: User description: "Integrate SBOM and VEX generation into the build-stage lifecycle while preserving OCI artifact storage and ensuring consistent propagation to primary, final, and cache repositories."

## Project Context

**Delivery Kit** is a Go CLI tool for full-cycle CI/CD to Kubernetes, built on top of werf with Deckhouse Platform extensions. The feature concerns the build, OCI artifact, registry, SBOM, VEX, and cleanup subsystems:

- **Build** (`pkg/build/`) — image build lifecycle and stage orchestration
- **SBOM** (`pkg/sbom/`) — SBOM generation, merging, caching, and publication
- **VEX** (`pkg/vex/`) — VEX validation, caching, and publication
- **OCI artifacts** (`pkg/oci/artifact/`) — fallback-tag artifact storage and propagation
- **Registry/storage** (`pkg/storage/`, `pkg/docker_registry/`) — primary, final, and cache repositories
- **Cleanup** (`pkg/cleaning/`) — lifecycle of image and artifact storage

## Problem Statement

SBOM and VEX are currently generated in separate post-build passes. Image manifests may be copied to `final-repo` or `cache-repo` before their OCI artifacts are generated, so artifact availability depends on repository options and on whether the image was built locally or restored from cache. SBOM has partial propagation support, while VEX does not consistently follow copied images.

This creates an unreliable supply-chain record: an image can be available in a destination repository while the SBOM or VEX needed to inspect it is missing there. Multi-platform images add another correctness risk because an artifact can be attached to the wrong descriptor if platform manifests are not resolved explicitly. Stages restored from a `--secondary-repo` can also lose their attached artifacts when copied into primary storage unless artifact propagation is part of the same lifecycle.

The build lifecycle needs one deterministic artifact flow that preserves the existing fallback-tag storage model without representing artifacts as image layers or changing the user-facing meaning of repository options. Because SBOM and VEX are OCI registry artifacts, enabling either one requires a configured registry destination; local-only builds must fail before image building starts.

## Clarifications

### Session 2026-09-01

- Q: For multi-platform images, should VEX always be attached to the top-level image index digest, and for single-platform images to the image manifest digest? → A: Option A — multi-platform VEX is attached to the image index digest; single-platform VEX is attached to the image manifest digest.
- Q: Should `--secondary-repo` be included in artifact propagation behavior? → A: Yes — artifacts attached to a suitable stage restored from a secondary repository are copied when that stage is stored in the primary repository.
- Q: What should happen when SBOM or VEX is enabled without any registry destination? → A: Fail early before image building starts with an actionable error requiring a registry destination.

## User Scenarios & Testing *(mandatory)

### User Story 1 — Artifacts follow published images (Priority: P1)

A delivery engineer builds an image with SBOM and/or VEX enabled. The resulting OCI artifacts are available wherever the corresponding image is published: the primary repository, the configured final repository, and the configured cache repositories according to their existing failure policies. When a suitable stage is restored from a `--secondary-repo`, its artifacts follow the stage into primary storage.

**Why this priority**: Consumers often access the final repository rather than the build repository. Missing attestations make the published image incomplete and undermine vulnerability and compliance workflows.

**Independent Test**: Build the same fixture with supported combinations of `--repo`, `--final-repo`, `--cache-repo`, and `--secondary-repo`, then retrieve SBOM and VEX by the image digest from every applicable destination.

**Acceptance Scenarios**:

1. **Given** an image with SBOM enabled and a VEX document, **when** it is built with a primary registry repository and without final or cache repositories, **then** both artifacts are available in the primary repository and the build behavior remains successful.
2. **Given** an image with SBOM and VEX enabled and `--final-repo`, **when** the build completes, **then** both artifacts are attached to the image manifest published in the final repository.
3. **Given** an image with SBOM and VEX enabled and one or more `--cache-repo` values, **when** the build completes, **then** artifacts are propagated to each cache repository where the corresponding image is stored, subject to existing cache failure policy.
4. **Given** both `--final-repo` and `--cache-repo`, **when** the build completes, **then** the artifacts are available in both destination classes.
5. **Given** primary and final repository addresses are identical, **when** the build completes, **then** the operation succeeds without creating duplicate artifact copies.
6. **Given** a suitable image stage is restored from `--secondary-repo`, **when** it is copied into primary storage, **then** all attached SBOM and VEX artifacts are copied to the corresponding primary image digest.
7. **Given** SBOM or VEX is enabled without any registry destination, **when** the build command starts, **then** it fails before image building with an actionable error requiring a registry destination.

---

### User Story 2 — Platform-specific artifacts describe the correct image (Priority: P1)

A delivery engineer builds a multi-platform image. Each platform-specific SBOM describes and is attached to the corresponding platform manifest. One VEX artifact describes the image at image level and is attached to the image index digest. For a single-platform image, VEX is attached to the image manifest digest. Consumers never receive an artifact silently attached to a different platform.

**Why this priority**: A platform-mismatched SBOM is a false supply-chain statement and can lead to incorrect vulnerability or compliance decisions.

**Independent Test**: Build a two-platform fixture, inspect the artifact subjects and platform metadata for both platform manifests, and verify the established VEX placement separately.

**Acceptance Scenarios**:

1. **Given** a multi-platform image with SBOM enabled, **when** the build completes, **then** each required platform manifest has the SBOM for that platform and its subject identifies that platform manifest.
2. **Given** platform-specific SBOM artifacts, **when** their metadata is inspected, **then** each artifact identifies the platform that was scanned.
3. **Given** a multi-platform image, **when** a platform-specific SBOM is queried, **then** the index digest is not used in place of the requested platform manifest digest.
4. **Given** a multi-platform image with VEX enabled, **when** the build completes, **then** exactly one VEX artifact is attached to the image index digest and no VEX artifact is attached to an individual platform manifest digest.

---

### User Story 3 — Rebuilds reuse or invalidate artifact results correctly (Priority: P1)

A delivery engineer repeats a build or changes its artifact-generation inputs. Unchanged inputs reuse the existing artifact; changed image content, scanner or merge inputs, VEX content, target platform, or signing identity produces a new artifact identity when that input affects the result.

**Why this priority**: Incorrect cache reuse silently publishes stale security metadata, while unnecessary regeneration increases build time and registry usage.

**Independent Test**: Run repeated builds with unchanged inputs, then change one input at a time and inspect cache decisions and artifact identities.

**Acceptance Scenarios**:

1. **Given** unchanged image and artifact-generation inputs, **when** the image is rebuilt, **then** the existing SBOM/VEX artifacts are reused and duplicate entries are not created.
2. **Given** a changed scanner option, merge input, or target platform, **when** the image is rebuilt, **then** the affected SBOM artifact is regenerated or republished with a new identity.
3. **Given** a changed VEX document, **when** the image is rebuilt, **then** the VEX artifact is regenerated or republished with a new identity.
4. **Given** a changed signing identity, **when** the image is rebuilt, **then** the affected signed artifact is republished rather than served from an incompatible cache entry.
5. **Given** an image restored from cache before the local build executes, **when** artifact processing runs, **then** the same cache and propagation rules apply as for an image built during the current run.

---

### User Story 4 — Registry failures have predictable consequences (Priority: P2)

A delivery engineer receives a clear result when artifact publication or propagation encounters a registry error. Final-repository failures do not leave a falsely successful release, while cache-repository failures follow the existing best-effort policy. A local-only build with SBOM or VEX enabled is rejected before any image build work begins.

**Why this priority**: Operators need to distinguish a missing release artifact from an optional cache mirror problem.

**Independent Test**: Run builds against an unavailable final repository, an unavailable cache repository, a missing secondary source artifact, and no registry destination, and verify the result and diagnostic behavior.

**Acceptance Scenarios**:

1. **Given** a failure while publishing or propagating an artifact to the final repository, **when** the build runs, **then** the build fails with an actionable error.
2. **Given** an unavailable cache repository, **when** the build runs, **then** the build follows the existing cache best-effort policy and reports the skipped propagation clearly.
3. **Given** a missing source artifact during propagation from a secondary repository, **when** the operation runs, **then** it does not silently claim that the destination contains the artifact.
4. **Given** a local-only build with SBOM or VEX enabled, **when** the build command starts, **then** it fails before image building and reports that a registry destination is required.
5. **Given** concurrent artifact attachments for one image digest, **when** all operations complete, **then** existing fallback-index convergence guarantees retain every artifact entry.

### Edge Cases

- A registry returns an absent fallback index because the image has no artifacts yet; the operation treats this according to the existing empty-index behavior.
- A final, cache, or primary repository contains an image whose digest differs from the source repository digest; the artifact is attached to the destination image digest, not the source digest.
- A suitable stage is found in a secondary repository but its attached artifact is missing; the primary copy must not be reported as artifact-complete.
- A multi-platform image has only one platform available in a destination; artifacts are propagated only for manifests that are actually present there.
- A configured cache or secondary repository is the same address as the primary repository; no redundant copy is performed.
- An artifact is already present in a destination; repeating the operation is idempotent and does not accumulate duplicate entries.
- Cleanup removes an image while its fallback artifact index remains; the existing orphan cleanup policy removes the resulting orphaned artifact index.
- SBOM or VEX is enabled without a registry destination; the build fails before image building with a clear requirement to configure a registry, rather than silently skipping artifact publication.
- A VEX document is image-level: for a multi-platform image it is attached only to the image index digest, and for a single-platform image it is attached to the image manifest digest; SBOMs use per-platform semantics.

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: The build MUST process enabled SBOM and VEX generation as part of the same deterministic image publication lifecycle, rather than as independent repository-dependent post-build operations.
- **FR-002**: The build MUST preserve OCI artifact semantics: SBOM and VEX MUST remain separate OCI artifacts and MUST NOT be represented as image layers, filesystem content, or fake container images.
- **FR-003**: For every artifact operation, the build MUST explicitly identify the image descriptor that the artifact describes and the destinations to which the artifact may be propagated.
- **FR-004**: For a single-platform image, an artifact MUST be attached to the digest of the image manifest actually published in that repository.
- **FR-005**: For a multi-platform image, platform-specific SBOMs MUST be attached to their corresponding platform manifest digests; an index digest MUST NOT substitute for a platform manifest digest.
- **FR-006**: VEX MUST be attached to the image manifest digest for a single-platform image and to the top-level image index digest for a multi-platform image; a multi-platform VEX MUST NOT be duplicated onto platform manifest digests.
- **FR-007**: The build MUST propagate SBOM and VEX artifacts from primary storage to the final repository and to configured cache repositories using one shared, idempotent propagation contract.
- **FR-007a**: When a suitable stage is restored from `--secondary-repo` and copied into primary storage, the build MUST propagate all attached SBOM and VEX artifacts to the corresponding primary image digest using the same shared, idempotent propagation contract.
- **FR-008**: Propagation MUST attach an artifact to the digest of the corresponding destination image, including when the source and destination image digests differ.
- **FR-009**: Propagation MUST skip identical source/destination addresses and MUST NOT create duplicate entries for an artifact already present with the same identity.
- **FR-010**: Final-repository publication or propagation failures MUST fail the build; cache-repository failures MUST retain the existing best-effort behavior and be distinguishable in build output.
- **FR-010a**: If SBOM or VEX is enabled and no registry destination is configured, the build MUST fail before image building starts with an actionable error requiring a registry destination.
- **FR-011**: Artifact cache identity MUST include every effective input that can change the corresponding artifact, including image dependency identity, scanner and merge inputs, VEX document content, target platform where applicable, artifact format version, and signer identity where applicable.
- **FR-012**: An unchanged set of effective inputs MUST reuse the existing artifact; changing an effective input MUST prevent a false cache hit and publish the corresponding new artifact identity.
- **FR-013**: The build MUST apply identical artifact processing rules whether an image was built during the current run or restored from a cache repository.
- **FR-014**: The implementation MUST preserve the current fallback-tag storage model, including per-platform artifact storage and existing artifact-to-image digest relationships.
- **FR-015**: Existing fallback-tag artifacts MUST remain readable, and concurrent attachment behavior MUST retain the existing convergence and deduplication guarantees.
- **FR-016**: Cleanup and purge operations MUST continue to remove orphaned artifact indexes in every repository where artifacts can be propagated, without leaving orphaned SBOM or VEX storage as a consequence of this feature.
- **FR-017**: User-facing meanings of `--repo`, `--final-repo`, `--cache-repo`, and `--secondary-repo` MUST remain unchanged except that SBOM and VEX artifacts consistently follow the corresponding published images.
- **FR-018**: The solution MUST NOT require migration to the OCI Referrers API.

### Key Entities

- **Image descriptor**: The published image manifest or image index/ platform manifest identity that determines which image an artifact describes.
- **Artifact stage**: A build-lifecycle operation that generates or publishes an OCI artifact without treating that artifact as a container image.
- **SBOM artifact**: An OCI artifact containing the software inventory for an image or platform manifest.
- **VEX artifact**: An OCI artifact containing vulnerability exploitability assessments; it is attached to the image manifest digest for single-platform images and to the top-level image index digest for multi-platform images.
- **Artifact identity**: The artifact type, checksum, platform where applicable, predicate kind, and signer identity needed to distinguish reusable results.
- **Artifact destination**: A primary, final, or cache repository together with the corresponding published image digest.
- **Secondary artifact source**: A secondary repository containing a suitable image stage and its attached artifacts before the stage is copied into primary storage.
- **Fallback artifact index**: The existing per-digest tag-based index that records artifacts attached to an image digest.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: In 100% of test builds covering primary-only, primary-plus-final, primary-plus-cache, primary-plus-final-plus-cache, and secondary-to-primary configurations, every enabled SBOM and VEX artifact is retrievable from each repository where the corresponding image is published.
- **SC-002**: In 100% of two-platform test builds, each platform-specific SBOM has the correct platform subject and metadata, and no platform SBOM is attached only to the top-level index digest.
- **SC-003**: Repeating an unchanged build produces no duplicate artifact entries and records an artifact cache hit for every unchanged artifact.
- **SC-004**: Changing each supported artifact-generation input in isolation causes the affected artifact to miss its cache; unchanged artifact types remain reusable when their own inputs are unchanged.
- **SC-005**: A final-repository propagation failure fails the build in every tested case, while an unavailable cache repository follows the existing best-effort outcome in every tested case.
- **SC-005a**: Every tested build with SBOM or VEX enabled and no registry destination fails before image building starts and reports that a registry destination is required.
- **SC-006**: Repeating propagation against the same destination is idempotent and leaves exactly one entry for each artifact identity, including under concurrent attachment tests.
- **SC-007**: Images restored from cache and images built locally produce equivalent artifact availability and placement for the same effective inputs.
- **SC-008**: Existing fallback-tag artifacts remain readable and existing cleanup tests continue to remove orphaned artifact indexes from primary and propagated repositories.
- **SC-009**: Existing builds without SBOM/VEX configuration and existing user-facing repository options, including `--secondary-repo`, continue to complete without behavior changes unrelated to artifact propagation.

## Assumptions

- The current fallback-tag storage model remains the compatibility baseline; no OCI Referrers API migration is needed for this feature.
- SBOM artifacts are platform-specific for multi-platform images. VEX is image-level: it is attached to the image index digest for multi-platform images and to the image manifest digest for single-platform images.
- Registry-level image copies may preserve a digest, while backend-mediated copies may produce a different destination digest; artifact propagation therefore resolves the destination subject explicitly.
- Final repositories are release destinations and are subject to fatal propagation errors; cache repositories remain optional mirrors governed by existing best-effort policy.
- `--secondary-repo` remains a source for restoring suitable stages; artifacts follow a stage when it is copied from secondary storage into primary storage.
- Existing SBOM generation, VEX generation, signing, checksum, fallback-index, and cleanup components are reused unless implementation proves a focused change necessary.
- A repository that is unavailable or has no corresponding image cannot receive an artifact; the resulting behavior follows the destination's established error policy.
- A registry destination is required whenever SBOM or VEX is enabled; local-only artifact publication is not a supported mode.
- No new user-facing flags or configuration syntax are required.

## Out of Scope

- Migration from fallback tags to the OCI Referrers API.
- Changing the fallback-tag schema or abandoning per-platform artifact storage.
- Embedding SBOM or VEX data into the image filesystem or image layers.
- Combining all platform SBOMs into a single index-level SBOM.
- Rewriting scanner, CycloneDX, DSSE, signing, or fallback-index subsystems without demonstrated necessity.
- Changing the public semantics of `--repo`, `--final-repo`, `--cache-repo`, or `--secondary-repo` beyond correcting artifact propagation.
- Introducing separate user-configurable cleanup policies for this feature.
