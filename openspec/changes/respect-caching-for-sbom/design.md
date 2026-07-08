## Context

The stage digest calculation in `calculateDigest()` (`pkg/build/build_phase.go`) determines whether a cached stage can be reused. It receives the following inputs:

- `BuildCacheVersion` — a hardcoded constant (`"1.2"`) in `pkg/image/const.go`.
- `StageName`, `StageDependencies`, `TargetPlatform`, signing options, previous stage digest, and base image reference.

The `build.sbom.enable` boolean (from `MetaBuildSbom.Enable`) currently has **no influence** on the stage digest. This means:

1. User builds with `build.sbom.enable=false` (default) → stages cached in the Container Registry.
2. User sets `build.sbom.enable=true` → stage digests do not change → cached stages are reused → `convergeSbomByImagesSets` runs but the cached stages were never built with SBOM → no SBOM artifacts are generated for those images.

The SBOM converge step (`convergeSbomByImagesSets` → `convergeImageSbom`) is called in `AfterImages`, **after** stages have already been resolved from cache. The SBOM artifact cache (`sbomStep.calculateStableChecksum` → `store.GetAttached`) is separate — it handles only whether the SBOM artifact for an already-processed image needs regeneration, not whether SBOM should run at all.

## Goals / Non-Goals

**Goals:**

- When `build.sbom.enable=true`, the stage cache digest must include an SBOM marker, invalidating cached stages from previous builds without SBOM and triggering a rebuild with SBOM generation.
- When `build.sbom.enable=false` (default), the stage digest MUST be unaffected — no extra arguments in the checksum calculation, preserving backward compatibility with existing cache.
- The solution must be minimal and scoped only to the `enable` boolean flag. The full SBOM configuration (GOST, standard, per-image overrides) is already handled by the SBOM artifact checksum.

**Non-Goals:**

- Changing how per-image SBOM configuration (GOST settings, SBOM standard) affects caching — these are correctly handled by the SBOM converge checksum.
- Modifying the SBOM artifact cache (`sbomStep.calculateStableChecksum`) — this already correctly invalidates when scan/merge options change.
- Any changes to local (non-repo) stages storage behavior.

## Decisions

### Decision 1: Append sbom-enable suffix to `BuildCacheVersion`

**Option A (chosen):** Modify `calculateDigest` to include an extra checksum argument derived from the SBOM enable state.
**Option B (rejected):** Bump the global `BuildCacheVersion` constant from `"1.2"` to `"1.3"`.

**Rationale for A:**
- Option B would invalidate **all** cached stages unconditionally, causing a full rebuild for every user regardless of whether they toggled SBOM. This is unnecessarily disruptive.
- Option A only invalidates stages for users who actually changed `build.sbom.enable`, leaving everyone else's cache intact.
- The SBOM enable state is accessible via `conveyor.EnableSbom()` at the point where `calculateDigest` is called (the phase has access to `phase.Conveyor`).

**Implementation approach:**
- In `calculateDigest`, after the existing checksum arguments are assembled, conditionally append an extra argument `"sbom_enabled"` **only when** `conveyor.EnableSbom()` returns `true`.
- When `conveyor.EnableSbom()` returns `false`, no extra argument is added — the digest calculation is identical to the current behavior, preserving cache compatibility.
- The function signature already receives `conveyor *Conveyor`, so no plumbing changes are needed.

### Decision 2: Use `conveyor.EnableSbom()` as the source of truth

The `conveyor.EnableSbom()` method already exists and reads `werfConfig.Meta.Build.Sbom.Enable`. Using this existing method avoids duplicating the configuration parsing logic and keeps the change minimal.

## Risks / Trade-offs

- **[Cache invalidation scope]**: Only impacts users who enable SBOM. Existing cached stages for users who never touch `build.sbom.enable` remain fully valid. When a user switches from `enable=false` to `enable=true`, cached stages from the `enable=false` build will be invalidated and rebuilt. This is intentional and correct — the cached stages don't have SBOM data and need regeneration.
- **[False positives]**: If SBOM enable state changes for reasons other than user intent (e.g., config file formatting), the cache would invalidate unnecessarily. This is acceptable since it only impacts users who explicitly modify their werf config.