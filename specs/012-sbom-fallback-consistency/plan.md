# Implementation Plan: Fix SBOM Fallback Annotation Loss

**Branch**: `012-sbom-fallback-consistency` | **Date**: 2026-07-29 | **Spec**: [spec.md](spec.md)

**Input**: Feature specification from `/specs/012-sbom-fallback-consistency/spec.md`

## Summary

The `Attach()` function in `pkg/oci/artifact/fallback.go` has a read-modify-write race condition: when multiple goroutines push SBOMs to the same parent digest concurrently, the CAS retry loop (3 tries, ~3.5s budget) can exhaust retries and lose annotations.

**Approach** (from research):
1. Add a **per-tag mutex** (established project pattern: `map[string]*sync.Mutex` + guard) that serializes the **entire** read-modify-write + consistency-wait operation.
2. The mutex lock covers: **(1)** read current index → **(2)** update → **(3)** write → **(4)** wait-for-tag with retry (consistency verification). Unlock only after consistency is confirmed.
3. Extend the **consistency wait budget** from 3 tries / ~3.5s to `30 * time.Second` max elapsed time (`backoff.WithMaxElapsedTime`, already used in codebase).
4. The public API (`Attach`, `GetAttached`, `GetAttachedContent`) remains unchanged.

## Technical Context

**Language/Version**: Go 1.24.10

**Primary Package**: `pkg/oci/artifact/fallback.go` — contains:
- `Attach(ctx, repo, parentDigest, artifactDesc, artifactType, imageName, opts...)` — target of the fix
- `pullFallbackIndex(ctx, repo, parentDigest, opts...)` — reads current index from mutable tag
- `pushFallbackIndex(ctx, repo, parentDigest, idx, opts...)` — writes updated index to mutable tag
- `updateFallbackIndex(current, artifactDesc, artifactType, imageName)` — appends/replaces descriptor
- `GetAttached(ctx, repo, parentDigest, artifactType, imageName, opts...)` — read path, unchanged per FR-005
- `PullFallbackIndex(ctx, repo, parentDigest, opts...)` — public wrapper, unchanged

**Current CAS mechanism** (being replaced):
- `backoff.NewExponentialBackOff()` with `InitialInterval: 500ms`, default multiplier (2x)
- `maxRetries = 3` → approximately 500ms + 1s + 2s = 3.5s max budget
- Read-after-write digest verification already implemented (lines 61-77) — but the retry wraps the entire RMW cycle, not just the consistency wait
- No per-tag serialization — two concurrent `Attach()` calls for different images (`frontend`, `backend`) share the same mutable tag and race

**Corrected algorithm** (with fix):

```
Enter Attach()
  │
  ├─ key = repo + "/" + FallbackTag(parentDigest)
  ├─ m = getTagMutex(key)
  ├─ m.Lock()
  │  ├─ (1) pullFallbackIndex()    // read current index
  │  ├─ (2) updateFallbackIndex()  // append/replace descriptor
  │  ├─ (3) pushFallbackIndex()    // write updated index
  │  └─ (4) backoff.Retry(...)     // wait-for-tag: read + digest verify
  │       ├─ pullFallbackIndex()
  │       └─ digest match? → done / retry
  └─ m.Unlock()
```

The mutex serializes **all** werf writers to the same tag. Inside the mutex, the retry loop only waits for **registry consistency** (our write to become visible). Since the mutex prevents concurrent in-process writes, CAS conflicts cannot occur, and the retry is purely for OCI registry eventual consistency.

**Repository structure affecting this feature**:
- `pkg/oci/artifact/fallback.go` — main implementation (250 lines)
- `pkg/oci/artifact/fallback_internal_test.go` — unit tests for `updateFallbackIndex` and `newStaticIndex`
- `pkg/oci/artifact/store.go` — `OCIStore` wrapper that calls `Attach()` and `GetAttached()`
- `pkg/oci/artifact/attach_integration_test.go` — integration tests using in-memory registry
- `pkg/attestation/ls.go` — consumer of `PullFallbackIndex`
- `test/e2e/sbom/regressions_test.go` — existing e2e regression test for annotation preservation (from `specs/010-sbom-fallback-annotation-loss`)
- `test/e2e/sbom/lifecycle_test.go` — existing e2e multi-image lifecycle test (build + merge SBOMs for 2 images)
- `test/e2e/sbom/_fixtures/regressions/manifest_annotation/` — isolated fixture for the regression test

## Constitution Check

*GATE: Must pass before Phase 0 research. Re-check after Phase 1 design.*

| Principle | Status | Notes |
|-----------|--------|-------|
| I. Simplicity Over Abstraction | ✅ PASS | Per-tag mutex with `map[string]*sync.Mutex` + guard is the simplest possible approach — exactly the pattern already used in `Conveyor` and `GitMapping`. No new abstractions. |
| II. Go Idiomatic Code | ✅ PASS | Uses established codebase conventions. Public API unchanged. Errors wrapped with context. |
| III. Minimal Public Surface | ✅ PASS | All new types/functions are package-private. Zero API changes. |
| IV. Test-Before-Merge | ✅ PASS | Existing tests + new concurrent integration test + new e2e test case. |
| V. Conventional Commits | ✅ PASS | Branch `012-sbom-fallback-consistency` follows convention. |

**GATE RESULT**: Pass — no violations. Complexity Tracking section is not needed.

## Project Structure

### Documentation (this feature)

```text
specs/012-sbom-fallback-consistency/
├── spec.md              # Feature specification
├── plan.md              # This file — implementation plan
├── research.md          # Phase 0 — research findings
├── data-model.md        # Phase 1 — data model design
├── contracts/           # Phase 1 — interface contracts (empty: no public API changes)
├── quickstart.md        # Phase 1 — validation guide
└── tasks.md             # Generated by speckit-tasks
```

### Source Code Changes

```text
pkg/oci/artifact/
├── fallback.go          # [MODIFY] Add per-tag mutex, restructure to lock→RMW→consistency-wait→unlock
├── fallback_test.go     # [NEW] Unit tests for mutex serialization + getTagMutex
├── fallback_internal_test.go  # [UNCHANGED] Existing unit tests
├── attach_integration_test.go # [MODIFY] Add concurrent push test case
└── store.go             # [UNCHANGED] Public API surface
test/e2e/sbom/
├── _fixtures/regressions/manifest_annotation/  # [UNCHANGED] Existing isolated fixture
├── lifecycle_test.go    # [UNCHANGED] Existing multi-image lifecycle test (runs with fix)
└── regressions_test.go  # [UNCHANGED] Existing e2e regression test (runs with fix)
```

## Complexity Tracking

> *Not needed — all Constitution gates passed without violations.*