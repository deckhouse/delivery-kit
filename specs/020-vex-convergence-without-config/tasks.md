# Tasks: VEX Convergence Without Configuration

**Feature**: `020-vex-convergence-without-config`

**Status**: migrated; implementation complete

**Input**: `spec.md` and `plan.md`, reverse-engineered from commit `b30d77ac1`.

## Phase 1: VEX convergence behavior

- [x] T001 [US1] Add an empty-image guard to `convergeImageVex` in `pkg/build/build_phase.go`.
- [x] T002 [US1] Move the nil/empty VEX configuration check before stage descriptor resolution in `pkg/build/build_phase.go`.
- [x] T003 [US2] Preserve the configured-VEX missing-descriptor error in `pkg/build/build_phase.go`.

## Phase 2: Descriptor selection

- [x] T004 [US2] Extract `vexStageDesc` for single-platform and registered multiplatform descriptor lookup in `pkg/build/build_phase.go`.
- [x] T005 [US2] Remove the unreachable synthetic multiplatform descriptor fallback in `pkg/build/build_phase.go`.

## Phase 3: Verification

- [x] T006 [US1] Update multiplatform convergence coverage for the no-VEX/no-descriptor no-op in `pkg/build/build_phase_test.go`.
- [x] T007 [US1] Add single-platform coverage for nil VEX and empty VEX document no-op behavior in `pkg/build/build_phase_test.go`.
- [x] T008 [US2] Add configured-VEX coverage for the unavailable descriptor error in `pkg/build/build_phase_test.go`.
- [x] T009 [US2] Add `vexStageDesc` coverage for reused single-platform, registered multiplatform, missing single-platform, and unregistered multiplatform cases in `pkg/build/build_phase_test.go`.

## Identified Gaps

- No dedicated test was added for the empty image-list guard, although the implementation handles it.
- No e2e test was added; the change is limited to build-phase behavior and is covered by co-located unit specifications.
- Broader VEX lifecycle behavior is intentionally not duplicated here; it is tracked by the existing VEX specifications.
