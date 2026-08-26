# Bug Fix: E2E SBOM/VEX cache-hit nil pointer

- **Slug**: e2e-sbom-vex-nil-pointer
- **Fixed**: 2026-08-26
- **Assessment**: ./assessment.md
- **Status**: partial

## Summary

Added a nil-safe stage descriptor accessor that prefers the cached content-tag descriptor and safely falls back to the last built stage descriptor. SBOM and VEX convergence now return descriptive errors instead of dereferencing unavailable stage state.

## Changes

| File | Change | Notes |
|------|--------|-------|
| `pkg/build/image/image.go` | modified | Added `GetLastNonEmptyStageDesc`; retained `GetLastNonEmptyStageImageInfo` through the safe accessor. |
| `pkg/build/build_phase.go` | modified | SBOM and VEX convergence use the safe descriptor; SBOM keeps multi-platform final-stage propagation and returns operation-specific errors for missing descriptors. |
| `pkg/build/build_phase_test.go` | modified | Added cache-hit descriptor fallback and missing-descriptor coverage. |


## Diff Highlights

- Cache-hit images with `contentTagDesc` no longer require `lastNonEmptyStage` to converge SBOM or VEX artifacts.
- Missing stage image, legacy image object, stage descriptor, or descriptor info is treated as unavailable rather than causing a panic.
- SBOM convergence computes the final-stage descriptor from the complete image set before processing individual platform images, preserving multi-platform artifact propagation.

## Tests Added or Updated

- `pkg/build/build_phase_test.go` — verifies that a reused image returns its content-tag descriptor even without a built stage, and that an image with neither descriptor returns nil.

## Local Verification

- Commands run: `TASK_X_REMOTE_TASKFILES=1 task format paths="pkg/build"` → passed.
- Commands run: `task test:unit paths="./pkg/build/..."` → passed; 122 specs passed.
- Mutation check: disabled the content-tag fallback in `GetLastNonEmptyStageDesc` → the cache-hit regression test failed at the expected assertion; restored the implementation and reran the suite successfully.
- Commands run: `task build` → timed out after 180 seconds. Output contained compiler warnings from `sqlite3` and static crypto linking, but no compilation error was captured.
- Commands not run: full lint, full unit suite, affected E2E suites, and `test:e2e:simple`; E2E execution requires the project’s external registry/Kubernetes environment and was deferred pending explicit environment/consent.
- Manual checks: scoped `git diff --check` passed for all authored files.

## Deviations from Assessment


- The assessment requested direct SBOM/VEX convergence tests and a missing-descriptor convergence test. The added focused tests exercise the shared accessor and its cache-hit/missing states, while the full convergence paths remain pending E2E/build verification.

## Follow-ups

- Re-run `task build` with a longer timeout and then complete the repository-mandated lint and broader unit checks.
- Run the affected SBOM and VEX E2E suites, followed by `test:e2e:simple`, in the configured CI-like environment.

- Run `/speckit-bug-test slug=e2e-sbom-vex-nil-pointer` after the remaining verification is complete.
