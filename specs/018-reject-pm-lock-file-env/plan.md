# Implementation Plan: reject PM_LOCK_FILE override

**Branch**: `018-reject-pm-lock-file-env` | **Date**: 2026-08-20 | **Spec**: [spec.md](spec.md)

**Input**: Feature specification from `/specs/018-reject-pm-lock-file-env/spec.md`

## Summary

Reject any `PM_LOCK_FILE` environment declaration on an `os-pm` package directive during configuration validation. The check belongs in `pkg/config.PackagesDirective.validate`, which is reached by parsed YAML conversion before package commands or builds begin. Reuse `metadata.ContainerFactoryIndexPath` so the actionable error and existing SBOM collector both identify `/var/lib/pm/index.json` as the only supported state path. Add co-located Ginkgo/Gomega table coverage for all required value classes and unaffected configurations.

## Technical Context

**Language/Version**: Go 1.24.10

**Primary Dependencies**:
- Existing `pkg/config` package directive validation and Ginkgo/Gomega tests.
- Existing `pkg/sbom/os_pm/metadata` fixed path constant.
- No new external dependencies.

**Storage**: No storage changes. SBOM state remains in the built image at `/var/lib/pm/index.json`.

**Testing**: Ginkgo + Gomega, co-located with `pkg/config` and existing SBOM metadata/collector tests as needed.

**Target Platform**: All supported CLI platforms; this is configuration validation and has no platform-specific behavior.

**Project Type**: Go CLI tool with YAML configuration parsing, package command generation, and SBOM collection.

**Performance Goals**: Add only an O(1) environment-map key lookup during existing directive validation; no measurable build-path impact.

**Constraints**: Preserve existing environment behavior except for the exact `PM_LOCK_FILE` key on `os-pm`; reject presence regardless of value; do not add a compatibility or warning-only mode; preserve the fixed SBOM path.

## Constitution Check

*GATE: Must pass before Phase 0 research. Re-checked after Phase 1 design.*

- **Simplicity Over Abstraction**: PASS — one scoped map-key check in existing validation; no new abstraction.
- **Go Idiomatic Code**: PASS — existing validation flow is reused; errors are actionable and contextual.
- **Minimal Public Surface**: PASS — no public API or dependency changes.
- **Test-Before-Merge**: PASS — tests are planned alongside source and use Ginkgo/Gomega.
- **Dependency Rules**: PASS — no new dependencies and no layer-boundary changes.
- **Build & Quality Gates**: PASS — implementation will use the required `task` format/build/lint/unit/e2e/integration commands.

No constitution violations require complexity justification.

## Phase 0: Research

Completed in [research.md](research.md). The research resolved the validation location, fixed SBOM path, testing strategy, and dependency questions.

## Phase 1: Design & Contracts

Completed:

- [data-model.md](data-model.md) — existing directive, prohibited key, fixed path, and validation transition.
- [contracts/configuration.md](contracts/configuration.md) — accepted/rejected user-facing YAML behavior.
- [quickstart.md](quickstart.md) — runnable focused and broader validation scenarios.

## Implementation outline

1. Update `pkg/config/packages_directive.go` so `os-pm` validation rejects `PM_LOCK_FILE` by key presence and reports the fixed SBOM path.
2. Add/adjust co-located Ginkgo tests in `pkg/config` covering custom, default, and empty values; no variable; unrelated `os-pm` variable; and non-`os-pm` environment behavior.
3. Preserve and verify the existing `metadata.ContainerFactoryIndexPath`-based SBOM collection behavior.
4. Run the required formatting, build, lint, unit, scoped e2e, and integration gates.

## Complexity Tracking

No violations.
