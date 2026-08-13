# Feature Specification: Per-Platform SBOM for Multi-Platform Images

**Feature Branch**: `feat/sbom/per-platform-sbom`

**Created**: 2026-08-06

**Status**: migrated

**Input**: Reverse-engineered from the implemented branch (10 commits, 20 files, +919/−70). Design history: `.omo/docs/c12-multiplatform-sbom-context.md` (§7 — user-approved decisions), plan `.omo/plans/c12-multiplatform-sbom.md`.

**Comparison**: `storage-model-comparison.md` compares the delivery-kit storage model with BuildKit (Moby BuildKit) and the OCI Specification reference model.

## Project Context

**Delivery Kit** is a Go CLI tool for full-cycle CI/CD to Kubernetes. It is built on top of werf with Deckhouse Platform extensions. Subsystems touched by this feature:

- **Build** (`pkg/build/`) — SBOM convergence during image build
- **SBOM** (`pkg/sbom/`) — SBOM generation, storage and retrieval
- **OCI artifacts** (`pkg/oci/artifact/`) — cosign-compatible artifact storage (fallback tags, subject, DSSE)
- **Cleanup** (`pkg/cleaning/`, `pkg/storage/`) — orphaned artifact collection
- **CLI** (`cmd/werf/sbom/`, `cmd/werf/attest/`) — SBOM and attestation commands

## Problem

For a multi-platform image (e.g. `linux/amd64` + `linux/arm64`) one SBOM was generated per image *name*, and it lied on every axis: syft scanned the index tag (pull resolved to the build host's platform, so the other platform's packages were absent), the `io.werf.target-platform` annotation claimed the first platform in the list, the base image SBOM was merged from the first platform only, and the in-toto `subject` pointed at the index digest instead of a platform manifest. Signing such an SBOM would certify a false statement, which blocked the parent SBOM-signing feature for multi-platform builds.

## User Scenarios & Testing *(mandatory)*

### User Story 1 — Multi-platform build produces one honest SBOM per platform (Priority: P1)

When a user builds a multi-platform image with `build.sbom.enable`, each platform manifest gets its own SBOM artifact: scanned from that platform's image, merged with that platform's base/import SBOMs, annotated with the real platform, and attached to the fallback tag of that platform's manifest digest with an in-toto `subject` equal to that digest.

**Why this priority**: Correctness of the SBOM is the whole point of generating one; a platform-ambiguous SBOM is worse than none once signing enters the picture.

**Independent Test**: Build a two-platform image against a test registry, then inspect the fallback tags of both platform manifest digests.

**Acceptance Scenarios**:

1. **Given** a two-platform build, **When** it completes, **Then** each platform manifest digest has exactly one attached SBOM artifact whose in-toto subject digest equals that platform manifest digest.
2. **Given** the generated artifacts, **When** their descriptors are read, **Then** `io.werf.target-platform` equals the platform that was actually scanned.
3. **Given** the index digest, **When** its fallback tag is inspected, **Then** no SBOM artifact is attached to it.
4. **Given** base images that differ per architecture, **When** SBOMs are generated, **Then** the per-platform SBOM contents differ accordingly.

---

### User Story 2 — SBOM cache works per platform without invalidating single-platform caches (Priority: P1)

Rebuilding an unchanged multi-platform project serves both platform SBOMs from the registry cache. Upgrading delivery-kit does not invalidate any existing single-platform SBOM cache.

**Acceptance Scenarios**:

1. **Given** an unchanged project, **When** it is rebuilt, **Then** each platform SBOM is reused from the registry (no regeneration).
2. **Given** a single-platform project built with the previous version, **When** it is rebuilt with this version, **Then** the SBOM checksum is byte-identical and the cache hits.

---

### User Story 3 — CLI addresses multi-platform SBOMs explicitly, never guessing (Priority: P2)

`werf sbom get` and `werf attest get/verify` accept `--platform`. A reference resolving to an image index without `--platform` fails with an error listing the available platforms and their digests. No host-platform default exists anywhere. `werf attest ls` on an index reference expands all platforms into one table with a PLATFORM column.

**Acceptance Scenarios**:

1. **Given** a multi-platform tag, **When** `werf sbom get --tag <tag>` runs without `--platform`, **Then** it fails listing `platform → digest` pairs.
2. **Given** the same tag, **When** `--platform linux/arm64` is added, **Then** the arm64 SBOM is returned.
3. **Given** a positional `IMAGE_NAME` built for several platforms, **When** no `--platform` is given, **Then** the command fails listing the built platforms (previously the first name match was silently used).
4. **Given** `werf attest ls` with an index reference, **When** it runs, **Then** attestations of all platforms appear in one table with a PLATFORM column.
5. **Given** a single-platform manifest digest, **When** `--platform` names a different platform, **Then** the command fails with a mismatch error (validated against the manifest config platform).
6. **Given** a platform with a variant (`linux/arm64/v8`), **When** it is passed to any sbom/attest command, **Then** it is normalized consistently (`linux/arm64`) before matching.

---

### User Story 4 — Legacy multi-platform base SBOMs are rejected, not silently merged (Priority: P2)

Building on top of a multi-platform base image whose SBOM was attached to the index digest by an older delivery-kit fails with an actionable error telling the user to rebuild the base with a newer version. This is an accepted breaking change: the legacy SBOM is platform-ambiguous and merging it would poison the new, honest SBOM.

**Acceptance Scenarios**:

1. **Given** a base whose SBOM exists only in the legacy index-attached format, **When** a dependent image is built, **Then** the build fails and the error contains both the existing label/attach guidance and the "rebuild the base image with a newer werf version" hint.

---

### User Story 5 — Cleanup collects per-platform SBOM artifacts without new deletion logic (Priority: P3)

When a multi-platform image is removed by cleanup, its platform stages are deleted in the same run, their fallback tags become orphans, and the existing digest-generic orphan pass collects them. A platform stage shared with another protected index keeps its SBOM (its parent still exists).

**Acceptance Scenarios**:

1. **Given** deleted platform manifests, **When** the orphan pass runs, **Then** their `sha256-<hex>` fallback tags are reported orphaned and deleted.
2. **Given** a platform manifest that still exists, **When** the orphan pass runs, **Then** its fallback tag is kept.

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: SBOM generation MUST run once per platform image: own stage descriptor, own base SBOM, own import SBOMs, own scan options, own platform annotation (`pkg/build/build_phase.go` — `convergeImageSbom` loops over `images`, `convergePlatformImageSbom` does one platform).
- **FR-002**: The in-toto statement subject MUST be the platform manifest digest; the artifact MUST be attached to the fallback tag of that digest.
- **FR-003**: The SBOM cache checksum MUST include the target platform when it is non-empty and MUST stay byte-identical for the empty platform (`calculateStableChecksum`).
- **FR-004**: The image pull for scanning MUST pass `PullOpts{TargetPlatform}` to the container backend (both Docker and Buildah backends honor it).
- **FR-005**: A missing base SBOM error MUST mention the legacy multi-platform format and instruct rebuilding the base (`baseSbomMissingError`).
- **FR-006**: `pkg/oci/artifact` MUST provide index platform resolution: `ResolvePlatformDigest` (index + platform → platform digest; index without platform → `ErrIndexPlatformRequired` listing platforms; non-index + platform → validate against manifest config platform), `ListIndexPlatforms`, `NormalizePlatform`, `PlatformMatches` (variant matching restricted to `os/arch` requests).
- **FR-007**: `werf sbom get` MUST support `--platform` in all three modes (`--tag`, `--digest`, positional), selecting the exported image by platform in positional mode.
- **FR-008**: `werf attest get` and `werf attest verify` MUST support `--platform`; `werf attest ls` MUST expand an index and render a PLATFORM column; `werf attest sign`, `werf sbom merge`, `werf sbom validate` MUST remain unchanged.
- **FR-009**: No SBOM artifact may be attached to the index digest (no merged index-level SBOM).
- **FR-010**: The fallback-index replace-semantics key `(artifactType, io.werf.image-name)` MUST remain unchanged (per-platform artifacts live in distinct fallback tags and cannot collide).

### Non-Functional Requirements

- **NFR-001**: Single-platform behavior (storage location, CLI UX, cache checksum) is byte-for-byte unchanged.
- **NFR-002**: Storage stays cosign-v3-compatible: `cosign verify-attestation --platform <index-ref>` discovery finds the artifacts; layout matches OCI image-spec 1.1 artifact guidelines and distribution-spec 1.1 referrers tag schema.
- **NFR-003**: Stage digests and content-based tags are unaffected (the platform enters only the SBOM artifact checksum annotation).

## Success Criteria *(mandatory)*

- **SC-001**: e2e (Linux, `multiplatform` label): two-platform build yields per-platform artifacts with correct subjects, truthful platform annotations, distinct subjects across platforms, nothing on the index digest, and cache reuse on rebuild.
- **SC-002**: Golden checksum tests prove the empty-platform checksum is unchanged and the platform-bearing checksum differs per platform.
- **SC-003**: Unit tests prove index resolution errors list available platforms, bare-OS input is rejected, variant input normalizes, and single-platform mismatch errors name the manifest platform.
- **SC-004**: Orphan-pass tests prove per-platform fallback tags are collected when platform manifests are gone and kept while they exist.

## Assumptions

- Per-platform stage descriptor `Info.Name` is a platform-unique stage tag (guaranteed by content-based tagging); byte-identical cross-platform builds would collide harmlessly (identical SBOM).
- CI runners for the e2e suite support pulling foreign-arch images (docker buildx + QEMU binfmt via `task test:setup:environment`).
- `WERF_PLATFORM` / `DOCKER_DEFAULT_PLATFORM` env vars may inject a platform default; the single-value constraint applies after env resolution.

## Out of Scope

- Merged index-level SBOM (decided against; can be added later without migration).
- Fallback lookup of legacy index-attached base SBOMs (rejected: would merge platform-ambiguous data).
- Format-version component in the checksum (tracked separately as C11).
- `sbom validate` changes (it is a local-file ISPRAS validator with no registry interaction).
