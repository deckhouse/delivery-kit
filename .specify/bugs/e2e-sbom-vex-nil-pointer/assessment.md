# Bug Assessment: E2E SBOM/VEX cache-hit nil pointer

- **Slug**: e2e-sbom-vex-nil-pointer
- **Created**: 2026-08-26
- **Source**: pasted CI log from `7_E2E tests (simple).txt` and subsequent code investigation
- **Verdict**: valid
- **Severity**: high

## Report (verbatim or summarized)

The CI command `task -p --yes test:e2e:simple -- --keep-going --timeout=85m --poll-progress-after=10m --poll-progress-interval=2m` failed in job `32871264280-3`.

The run reported failures in the `build`, `sbom`, `stages/copy`, and `vex` suites. The repeated primary failure was:

```text
panic: runtime error: invalid memory address or nil pointer dereference

github.com/werf/werf/v2/pkg/build.(*BuildPhase).convergeImageVex
    pkg/build/build_phase.go:1733
```

The SBOM suite showed an analogous panic at `pkg/build/build_phase.go:363`.


## Symptom

A remote-storage `werf build` panics while converging SBOM or VEX artifacts for an image resolved from the cache instead of returning an error or successfully reusing the cached image. The expected behavior is that initial builds, cache hits, and rebuilds complete without a nil-pointer panic.


## Reproduction

1. Run the simple E2E suite in the CI environment:
   `task -p --yes test:e2e:simple -- --keep-going --timeout=85m --poll-progress-after=10m --poll-progress-interval=2m`.
2. Execute scenarios that use remote stages storage and enable SBOM or VEX processing.
3. Build an image, then rebuild it or use a content-tag cache hit so that the image has `contentTagDesc` but no `lastNonEmptyStage`.

The minimal reproduction should be a focused unit test that constructs the cache-hit state directly: `contentTagDesc` is set while `lastNonEmptyStage` is unset. A full E2E run should remain a confirmation test rather than the primary isolation mechanism.

## Suspected Code Paths

- `pkg/build/build_phase.go:362-363` — `convergePlatformImageSbom` unconditionally evaluates `img.GetLastNonEmptyStage().GetStageImage().Image.GetStageDesc()`.
- `pkg/build/build_phase.go:423-424` — SBOM propagation again obtains the final descriptor through `GetLastNonEmptyStage()`.
- `pkg/build/build_phase.go:1724-1734` — `convergeImageVex` unconditionally evaluates `primaryImg.GetLastNonEmptyStage().GetStageImage().Image.GetStageDesc()` for a single-platform image.
- `pkg/build/build_phase.go:739-746` — cache-hit handling sets `contentTagDesc`, marks `AnchorReused`, and skips image-stage processing.
- `pkg/build/conveyor.go:941-945` — when `contentTagDesc` is available, image processing returns early.
- `pkg/build/build_phase.go:764-767` — `lastNonEmptyStage` is set in `AfterImageStages`, which is skipped by the cache-hit short circuit.
- `pkg/build/image/image.go:347-368` — `GetLastNonEmptyStageImageInfo` already prefers `contentTagDesc` and performs nil checks, demonstrating the safe access pattern.


## Root Cause Hypothesis

**Confidence: high.** On a cache hit, `BeforeImageStages` resolves and stores the already-built descriptor in `Image.contentTagDesc`, then `Conveyor.doImage` skips stage processing. Consequently, `AfterImageStages` does not set `lastNonEmptyStage`. The SBOM and VEX convergence paths nevertheless dereference `GetLastNonEmptyStage()` unconditionally, causing the observed SIGSEGV. The failure is backend-independent because both Docker and Native Buildah eventually use the same build-phase convergence code.

## Proposed Remediation

**Preferred**: introduce a single safe stage-descriptor accessor for artifact convergence. For a cache-hit image it should use `contentTagDesc`; otherwise it should obtain the descriptor from `lastNonEmptyStage` with checks for missing stage image, image object, and stage descriptor. Use this accessor in both SBOM and VEX convergence. Preserve the existing multi-platform behavior that selects the index descriptor for VEX/SBOM artifacts. If the descriptor is genuinely unavailable, return an operation-specific error containing the image name instead of panicking.


**Alternatives**:

- Restore `lastNonEmptyStage` during cache-hit resolution. This keeps existing consumers unchanged but couples cache restoration to stage lifecycle internals and may require reconstructing more stage state than is needed for artifact publication.
- Add only nil checks that skip SBOM/VEX convergence. This prevents the panic but silently omits requested artifacts and is therefore suitable only as a temporary diagnostic fallback.

**Files likely to change**:

- `pkg/build/build_phase.go`
- `pkg/build/image/image.go` or a suitable build-phase helper location
- `pkg/build/build_phase_test.go` and/or focused build tests


**Tests to add or update**:

- Test SBOM convergence for an image with `contentTagDesc` set and `lastNonEmptyStage` unset.
- Test VEX convergence for the same cache-hit state.
- Test that a missing descriptor returns a descriptive error rather than panicking.
- Preserve coverage for single-platform and multi-platform descriptor selection.
- Run the affected E2E suites, then `test:e2e:simple`, after the fix.

## Risks & Considerations

- The descriptor accessor must preserve the distinction between a single-platform content-tag descriptor and a multi-platform index descriptor.
- Returning an error for an invalid internal state changes a process panic into a normal build failure, which is safer but may expose previously hidden invalid states.
- Skipping artifact generation on descriptor absence would produce incomplete SBOM/VEX results and should not be the preferred fix.

- The Ginkgo CLI mismatch (`2.20.1` CLI versus `2.28.1` imported packages) is documented context only. It is not part of this fix and is not the observed SIGSEGV cause.
- No production data migration, public API change, or security-sensitive behavior change is required by the proposed fix.

## Open Questions
