# Feature Specification: SBOM Cache Invalidation

**Feature Branch**: `001-sbom-cache-invalidation`

**Created**: 2026-07-15

**Status**: Migrated

**Input**: User description: "Conditionally include SBOM enable state in stage digest calculation to invalidate build cache when SBOM generation is toggled"

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

<!--
  IMPORTANT: User stories should be PRIORITIZED as user journeys ordered by importance.
  Each user story/journey must be INDEPENDENTLY TESTABLE — meaning if you implement just ONE of them,
  you should still have a viable MVP (Minimum Viable Product) that delivers value.

  Assign priorities (P1, P2, P3, etc.) to each story, where P1 is the most critical.
  Think of each story as a standalone slice of functionality that can be:
  - Developed independently
  - Tested independently
  - Deployed independently
  - Demonstrated to users independently
-->

### User Story 1 — SBOM Toggle Invalidates Build Cache (Priority: P1)

A user who has been building images without SBOM decides to enable SBOM generation. They expect the build to detect the configuration change, invalidate the cached stages, rebuild with SBOM enabled, and produce images with SBOM artifacts attached.

**Why this priority**: This is the core use case — ensuring SBOM enablement triggers a cache invalidation so that SBOM artifacts are generated. Without this, enabling SBOM would have no effect on existing builds.

**Independent Test**: Can be fully tested by building an image with `build.sbom.enable=false`, caching all stages, then changing to `build.sbom.enable=true` and verifying that all stages are rebuilt with SBOM output.

**Acceptance Scenarios**:

1. **Given** an image was previously built and cached with `build.sbom.enable: false`, **When** a user sets `build.sbom.enable: true` in `werf.yaml` and triggers a build, **Then** the stage digest for each image SHALL differ from the cached stages
2. **Given** the stage digests differ, **When** the build proceeds, **Then** all stages SHALL be rebuilt with SBOM generation enabled
3. **Given** the stages are rebuilt, **When** the build completes, **Then** SBOM artifacts SHALL be generated and attached to the published images

---

### User Story 2 — SBOM Disabled Build Reuses Cache (Priority: P2)

A user who has never enabled SBOM continues building images. They expect that existing cached stages are reused and no SBOM artifacts are generated, preserving build performance.

**Why this priority**: This is the default behavior path — ensuring backward compatibility with existing caches. Most users will have SBOM disabled; this path must remain fast and stable.

**Independent Test**: Can be fully tested by building an image with `build.sbom.enable=false` twice in a row and verifying the second build reuses all cached stages without generating SBOM artifacts.

**Acceptance Scenarios**:

1. **Given** an image was previously built and cached with `build.sbom.enable: false`, **When** a user triggers a build with `build.sbom.enable: false`, **Then** the stage digest for each image SHALL remain unchanged
2. **Given** the stage digests are unchanged, **When** the build proceeds, **Then** previously cached stages SHALL be reused
3. **Given** cached stages are reused, **When** the build completes, **Then** no SBOM artifacts SHALL be generated

---

### User Story 3 — SBOM Enabled Build Preserves Cache (Priority: P3)

A user who has SBOM enabled rebuilds an image without configuration changes. They expect that all cached stages are reused and SBOM artifacts from the cached build are preserved, avoiding unnecessary rebuilds.

**Why this priority**: This maintains build performance when SBOM is already enabled. Users who always build with SBOM should not experience cache misses.

**Independent Test**: Can be fully tested by building an image with `build.sbom.enable=true`, then rebuilding with the same configuration and verifying all cached stages are reused.

**Acceptance Scenarios**:

1. **Given** an image was previously built and cached with `build.sbom.enable: true`, **When** a user triggers a build with `build.sbom.enable: true` (and all other cache inputs are identical), **Then** the stage digest for each image SHALL remain unchanged
2. **Given** the stage digests are unchanged, **When** the build proceeds, **Then** previously cached stages SHALL be reused
3. **Given** cached stages are reused, **When** the build completes, **Then** the SBOM artifacts from the cached build SHALL be preserved

---

### User Story 4 — GOST Changes Without Cache Invalidation (Priority: P4)

A user who has SBOM enabled modifies GOST (Government SBOM standard) configuration settings. They expect that stage caches remain valid (since only the SBOM enable flag affects cache), but SBOM artifacts are regenerated with the new GOST requirements during the converge step.

**Why this priority**: This is an optimization use case — ensuring that non-cache-relevant SBOM configuration changes don't trigger costly image rebuilds while still producing correct SBOM artifacts.

**Independent Test**: Can be fully tested by building an image with SBOM enabled and specific GOST settings, then changing the GOST settings and verifying stages are reused while SBOM artifact checksums change.

**Acceptance Scenarios**:

1. **Given** an image was previously built with `build.sbom.enable: true` and specific GOST settings, **When** a user modifies `build.sbom.gost` settings in `werf.yaml` (while `build.sbom.enable` remains `true`), **Then** the stage digest SHALL NOT change
2. **Given** the stage digest did not change, **When** the build proceeds, **Then** cached stages remain valid and are reused
3. **Given** cached stages are reused, **When** the converge step runs, **Then** SBOM artifact checksums SHALL change and SBOM artifacts SHALL be regenerated

### Edge Cases

- What happens when both `build.sbom.enable` and GOST settings change simultaneously? The stage cache is invalidated by the enable toggle change, and GOST changes are handled during converge.
- How does the system handle per-image SBOM overrides that toggle enable? Each image's enable state is evaluated independently for cache invalidation purposes.
- What happens if the SBOM marker is added to the digest but the stage was cached before this feature was introduced? The new digest will differ from the old cached digest, causing a rebuild — which is the correct behavior since the old cache has no SBOM artifacts.

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: System MUST include a conditional SBOM marker in the stage digest when `build.sbom.enable=true`
- **FR-002**: System MUST NOT include any SBOM-related marker in the stage digest when `build.sbom.enable=false` (default), preserving backward compatibility with existing cache
- **FR-003**: SBOM enable state (`build.sbom.enable`) MUST be the only SBOM configuration option that affects stage digest calculation
- **FR-004**: GOST configuration changes (`build.sbom.gost`) MUST NOT affect the stage digest
- **FR-005**: SBOM standard selection changes MUST NOT affect the stage digest
- **FR-006**: Per-image SBOM configuration overrides that change the effective enable state for an image MUST affect that image's stage digest
- **FR-007**: Per-image SBOM configuration overrides that change non-enable settings (GOST, standard) MUST NOT affect the stage digest
- **FR-008**: When stage digests differ due to SBOM enable state change, all stages for the affected image SHALL be rebuilt with SBOM generation enabled
- **FR-009**: When stage digests are unchanged (SBOM disabled consistently), no SBOM artifacts SHALL be generated
- **FR-010**: When stage digests are unchanged (SBOM enabled consistently), SBOM artifacts from the cached build SHALL be preserved
- **FR-011**: When only GOST settings change (SBOM remains enabled), SBOM artifact checksums MUST change and artifacts MUST be regenerated during the converge step

### Go-Specific Requirements *(when applicable)*

- All public functions MUST accept `context.Context` as the first parameter
- Errors MUST be wrapped with `fmt.Errorf("doing something: %w", err)`
- Use `samber/lo` helpers (`lo.Filter`, `lo.Map`, `lo.Contains`, etc.) where appropriate
- Optional arguments use `<FunctionName>Options` struct — never functional options
- Add `var _ Interface = (*Impl)(nil)` compile-time check for each interface implementation

### Key Entities *(include if feature involves data)*

- **Stage Digest**: A hash computed per build stage that determines whether a cached stage can be reused. Now conditionally includes an SBOM enable marker.
- **SBOM Enable Marker**: A token incorporated into the stage digest when SBOM generation is enabled. Absent when SBOM is disabled.
- **SBOM Artifact**: Generated SBOM document attached to a published container image. Subject to GOST and standard configuration.
- **Stage Cache**: Stored build stage outputs indexed by digest. Cache hits avoid rebuilding stages.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: Enabling SBOM (`build.sbom.enable=true`) on a previously SBOM-disabled build results in all stages being rebuilt (0% cache hit rate for the first build after toggle)
- **SC-002**: Disabling SBOM (`build.sbom.enable=false`) on a previously SBOM-disabled build results in 100% cache hit rate — all stages reused from cache
- **SC-003**: Enabling SBOM on a previously SBOM-enabled build (no other changes) results in 100% cache hit rate — all stages reused
- **SC-004**: Changing GOST settings while SBOM remains enabled results in 100% stage cache hit rate, with SBOM artifacts regenerated
- **SC-005**: No performance regression for the default case (`build.sbom.enable=false`) — stage digest computation overhead is negligible

## Assumptions

- The SBOM subsystem (`pkg/sbom/`) handles the actual SBOM generation and GOST compliance — the stage cache invalidation mechanism only needs to trigger rebuilds
- The converge step is the appropriate place for SBOM artifact regeneration when only GOST settings change
- Per-image SBOM overrides follow the same enable/non-enable distinction as the global configuration
- The existing stage digest computation mechanism is extensible enough to incorporate the conditional SBOM marker
- Users set `build.sbom.enable` in the `werf.yaml` configuration file
- Backward compatibility with existing cached stages (where no SBOM marker exists) is required
