# Implementation Plan: Reduce PURL Resolver Retries Duration

**Branch**: `011-reduce-purl-retries-duration` | **Date**: 2026-07-27 | **Spec**: [spec.md](spec.md)

**Input**: Feature specification from `specs/011-reduce-purl-retries-duration/spec.md`

**Note**: This template is filled in by the `/speckit-plan` command. See `.specify/templates/plan-template.md` for the execution workflow.

## Summary

Reduce the PURL resolution retry window from 30 s to 10 s (3× reduction) and lower the HTTP client timeout from 30 s to 5 s so that a single hung request does not exhaust the entire retry budget. This is a pure configuration change in the `externalref` service: two hardcoded constants in `pkg/sbom/externalref/service.go` and their default value in `NewService()`.

## Technical Context

**Language/Version**: Go 1.24.10

**Primary Dependencies**:
- `github.com/cenkalti/backoff/v5` — exponential backoff retry (already used)
- `github.com/CycloneDX/cyclonedx-go` — SBOM data model (already used)
- `golang.org/x/sync/errgroup` — parallel resolution with bounded concurrency (already used)

**Affected Package**: `pkg/sbom/externalref/` — specifically `service.go` (retry parameters, HTTP timeout) and `patcher.go` (default service construction).

**No changes needed** to:
- `enricher.go` — parallel resolution logic, error aggregation, concurrency limit
- `model.go` — data types
- `patcher.go` — wiring (the `NewExternalRefPatcher` function uses `NewService` with defaults, which will pick up the new timeout)

**Testing**: Ginkgo tests in `service_test.go` and `enricher_test.go` must be updated to verify the new retry window and timeout.

**Target Platform**: Linux (amd64/arm64)

**Project Type**: CLI tool (Go binary via `cmd/werf/main.go`)

**Performance Goals**: PURL resolution failure path must complete within 10 s per PURL (down from 30 s).

**Constraints**: No new external dependencies; no API changes; no breaking changes to `ServiceConfig` or `Service` public API.

**Scale/Scope**: Single file change (`service.go`) with two constant updates and one default value update. Test updates in `service_test.go`.

## Constitution Check

*GATE: Must pass before Phase 0 research. Re-check after Phase 1 design.*

| Gate | Status | Notes |
|------|--------|-------|
| I. Simplicity Over Abstraction | ✅ PASS | Simple constant change — no new interfaces, generics, or abstractions |
| II. Go Idiomatic Code | ✅ PASS | No changes to function signatures, error handling, or naming conventions |
| III. Minimal Public Surface | ✅ PASS | No public API changes — `ServiceConfig` and `Service` signatures unchanged |
| IV. Test-Before-Merge | ✅ PASS | Existing tests will be updated to verify new timing constants |
| V. Conventional Commits | ✅ PASS | Commit message will follow conventional commits format |

**No violations found.** Complexity tracking not needed.

## Project Structure

### Documentation (this feature)

```text
specs/011-reduce-purl-retries-duration/
├── spec.md              # Feature specification
├── plan.md              # This file
├── research.md          # Phase 0 output
├── data-model.md        # Phase 1 output
├── quickstart.md        # Phase 1 output
├── contracts/           # Phase 1 output
└── tasks.md             # Phase 2 output (/speckit-tasks command)
```

### Source Code (repository root)

```text
pkg/sbom/externalref/
├── service.go           # TARGET: retry parameters and HTTP timeout (lines 34-35, 59)
├── service_test.go      # TARGET: update tests for new timing
├── enricher.go          # NO CHANGE — parallel resolution logic stays
├── enricher_test.go     # NO CHANGE — enricher tests use mocks, timing-independent
├── model.go             # NO CHANGE — data types
├── patcher.go           # NO CHANGE — wiring, inherits defaults from NewService
├── helpers_test.go      # NO CHANGE — mock resolver
└── suite_test.go        # NO CHANGE — test suite
```

## Complexity Tracking

No constitution violations — not applicable.

## Change Summary

| Location | Current Value | Target Value | Rationale |
|----------|--------------|--------------|-----------|
| `service.go:59` — `backoff.WithMaxElapsedTime` | 30 s | 10 s | 3× reduction in retry budget |
| `service.go:35` — `timeout` default in `NewService()` | 30 s | 5 s | Allow room for retries within budget |
| `service.go:40` — `http.Client.Timeout` (when nil client) | 30 s | 5 s | Same as above (code path converges) |