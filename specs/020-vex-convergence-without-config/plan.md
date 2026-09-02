# Implementation Plan: VEX Convergence Without Configuration

**Branch**: `fix/vex/skip-converge-without-config` | **Date**: 2026-09-02 | **Spec**: `spec.md`

**Status**: migrated

**Input**: Reverse-engineered from commit `b30d77ac1` and the resulting source/tests.

## Summary

Move the VEX configuration guard to the beginning of `convergeImageVex`, so images that do not configure VEX return before stage descriptor resolution. Extract descriptor selection into `vexStageDesc`, retain the valid single-platform and registered multiplatform paths, and remove the unreachable synthetic multiplatform fallback.

## Technical Context

**Language/Version**: Go 1.24.10

**Primary Dependencies**:
- Ginkgo v2 and Gomega for co-located tests
- Existing werf image model and build pipeline packages
- Existing VEX configuration and Giterminism file-reader infrastructure

**Storage**: Existing image stage storage and registry-backed build pipeline; no storage model changes.

**Testing**: Unit tests in `pkg/build/build_phase_test.go` using Ginkgo and Gomega.

**Target Platform**: Existing werf build targets; no platform-specific implementation change.

## Existing Project Structure

```text
pkg/build/
├── build_phase.go       # VEX convergence and descriptor selection
└── build_phase_test.go  # BuildPhase unit specifications
```

## Implementation Details

1. Add `vexStageDesc(name, images)` as a focused descriptor-selection helper.
2. Return the single image's last non-empty descriptor for single-platform input.
3. Return the registered multiplatform image descriptor for multiplatform input.
4. Return nil when no applicable descriptor exists; do not construct a temporary multiplatform image.
5. In `convergeImageVex`, return early for an empty image list, nil VEX configuration, or an empty VEX document.
6. Resolve the descriptor only after VEX is confirmed to be configured.
7. Preserve the existing error text and all subsequent VEX file reading/publishing logic.

## Constitution Check

- **Simplicity**: The change extracts one small private helper and removes an unreachable fallback.
- **Go idioms**: Guard clauses are used; no public API or dependency changes are introduced.
- **Minimal public surface**: `vexStageDesc` and `convergeImageVex` remain private methods.
- **Test-before-merge**: Coverage is co-located and uses Ginkgo/Gomega.
- **Build and quality gates**: The repository-required task-based formatting, build, lint, unit, e2e, and integration checks apply when validating the implementation.

## Complexity Tracking

No constitution violations or new complexity were identified.

## Migration Notes

The implementation already exists. This plan records the actual approach rather than prescribing additional work. The original code's synthetic multiplatform fallback was removed because `NewMultiplatformImage` does not populate `stageDesc`, making that fallback unable to provide a descriptor.
