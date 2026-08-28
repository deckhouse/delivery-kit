# Bug Fix: SBOM/VEX regressions in v3 migration

- **Slug**: v3-sbom-vex-regressions
- **Fixed**: 2026-08-28
- **Assessment**: ./assessment.md
- **Status**: applied

## Summary

The multi-image VEX path now returns the same descriptive stage-descriptor error as the single-image path instead of passing nil into VEX convergence. `werf sbom get` no longer initializes obsolete Kubernetes connection flags during command construction.

## Changes

| File | Change | Notes |
|------|--------|-------|
| `pkg/build/build_phase.go` | modified | Validate the selected multi-image stage descriptor before VEX convergence. |
| `pkg/build/build_phase_test.go` | modified | Add regression coverage for unavailable and available multi-image stage descriptors. |
| `cmd/werf/sbom/get/get.go` | modified | Remove stale `SetupKubeConnectionFlags` initialization. |
| `cmd/werf/sbom/get/get_test.go` | modified | Verify SBOM, digest, tag, and platform flags are registered while Kubernetes flags are absent. |

## Diff Highlights

The multi-image branch now checks `stageDesc == nil` and returns:

```text
unable to converge VEX for image %q: stage descriptor is unavailable
```

The `sbom get` command no longer calls `common.SetupKubeConnectionFlags`.

## Tests Added or Updated

- `pkg/build/build_phase_test.go` — verifies multi-image VEX convergence returns a descriptive error when the descriptor is unavailable and proceeds when it is available.
- `cmd/werf/sbom/get/get_test.go` — verifies command construction exposes the intended SBOM/platform flags without Kubernetes flags.

## Local Verification

- Commands run: `TASK_X_REMOTE_TASKFILES=1 task format paths="pkg/build cmd/werf/sbom/get"` → blocked; Taskfile remote download timed out.
- Commands run: `TASK_X_REMOTE_TASKFILES=1 task test:unit paths="./pkg/build/..."` → blocked; Taskfile remote download timed out.
- Commands run: `TASK_X_REMOTE_TASKFILES=1 task test:unit paths="./cmd/werf/sbom/get/..."` → blocked; Taskfile remote download timed out.
- Commands run: `git --no-pager diff --check -- pkg/build/build_phase.go pkg/build/build_phase_test.go cmd/werf/sbom/get/get.go cmd/werf/sbom/get/get_test.go` → passed.
- Manual checks: confirmed `vexStep.Converge` dereferences `stageDesc` immediately and confirmed the removed initializer was the only Kubernetes setup call in `sbom get` construction.

## Deviations from Assessment

The assessment proposed exercising the exact warm-cache state and validating all `--tag`, `--digest`, and image-name execution modes. Those runtime checks could not be run because the mandated Taskfile download timed out. The added command test covers construction and flag exposure; it does not execute registry-dependent retrieval.

## Follow-ups

- Run `/speckit-bug-test slug=v3-sbom-vex-regressions` when network access to the remote Taskfile is available.
- Confirm the underlying lifecycle that leaves `MultiplatformImage.stageDesc` unset during cache hits; this fix prevents the panic but does not populate the missing descriptor.
