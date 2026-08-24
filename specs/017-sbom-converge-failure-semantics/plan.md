# Implementation Plan: SBOM Converge Failure Semantics

**Branch**: `fix/sbom/converge-failure-semantics` | **Date**: 2026-08-17 | **Spec**: [spec.md](./spec.md)

**Input**: Feature specification from `/specs/017-sbom-converge-failure-semantics/spec.md`

## Summary

SBOM converge defers PURL enrichment failures for one aggregated report, but a failed image's SBOM is never published, so dependents hard-fail with a misleading "rebuild with SBOM generation enabled" error that also loses the report; and a dead resolver burns every image's full retry budget. Fix: classify resolution failures as content vs infrastructure inside the resolver client (`pkg/sbom/externalref/service.go`, where the retryability decision already lives), add a process-wide circuit breaker that trips after a fixed number of consecutive infrastructure failures, skip dependents of failed images with the recorded root cause, emit the aggregated report on every exit path of `convergeSbomByImagesSets` via defer, and fix five log-quality gaps (error next to FAILED, GOST warning once, repo addresses, timed resolution section, contextualized multiple-entries warning). No new flags or configuration.

## Technical Context

**Language/Version**: Go 1.24.10

**Primary Dependencies**:
- **SBOM**: `CycloneDX/cyclonedx-go`; PURL resolution retry via `cenkalti/backoff/v5` (existing in `pkg/sbom/externalref`)
- **Logging**: `werf/logboek` (log blocks, warnings)
- **Utilities**: `samber/lo`, `golang.org/x/sync/errgroup` (existing enricher parallelism)

**Touched code** (all existing, no new packages):
- `pkg/sbom/externalref/service.go` — failure classification, breaker check in `Resolve`
- `pkg/sbom/externalref/patcher.go` — breaker plumbed through `NewExternalRefPatcher`
- `pkg/sbom/externalref/enricher.go` — unchanged aggregation; classified errors flow through
- `pkg/build/build_phase.go` — `convergeSbomByImagesSets` (defer report, breaker lifetime, skip logic), `collectBaseImageSbom` (advice gating)
- `pkg/build/sbom_step.go` — `baseSbomMissingError` gating, GOST once-per-process, repo address in `PropagateArtifacts`, timed external-ref section in patcher loop
- `pkg/oci/artifact/fallback.go` — contextualized multiple-entries warning

**Storage**: n/a (no schema/registry format changes)

**Testing**: Ginkgo + Gomega; table-driven (`DescribeTable`); mocks via `httptest` (existing pattern in `pkg/sbom/externalref/helpers_test.go`)

**Target Platform**: Linux (amd64/arm64); unit tests run anywhere

**Project Type**: CLI tool (Go binary via `cmd/werf/main.go`) — no CLI surface changes

**Performance Goals**: resolver-outage wall-clock bounded by breaker threshold + in-flight retry budgets (independent of image count) — SC-003

**Constraints**: no new CLI flags/config (FR-015); aggregated report format preserved (`wiki/pages/error-aggregation-strategy.md`); per-request retry policy from spec 011 unchanged

**Scale/Scope**: ~6 files touched, 2 new small types (FailureClass, ResolverBreaker), no new packages

## Constitution Check

*GATE: Must pass before Phase 0 research. Re-check after Phase 1 design.*

| Principle | Status | Notes |
|---|---|---|
| I. Simplicity Over Abstraction | PASS | No new interfaces; breaker is a concrete struct passed explicitly; classification is a typed error, not an abstraction layer. External-ref patcher special-cased at the call site instead of extending the patcher interface (research R6.6). |
| II. Go Idiomatic Code | PASS | `context.Context` first everywhere touched; errors wrapped with action context; sentinel errors + `errors.Is`/`As`; string-typed enum with type-name prefix (no `iota`). |
| III. Minimal Public Surface | PASS | New exported names limited to what crosses the package boundary: `FailureClass` values, `ErrResolverUnavailable`, breaker constructor + option field on `ServiceConfig`/patcher options. Threshold is an unexported constant. |
| IV. Test-Before-Merge | PASS (planned) | Ginkgo/Gomega table-driven tests co-located; breaker/classification/skip/exit-path coverage enumerated in quickstart.md; e2e via `task test:e2e labelFilter="sbom"`. |

**Post-design re-check**: PASS — design introduces two small concrete types and extends one existing `sync.Map` value; no violations to justify (Complexity Tracking empty).

**Environment note**: `task test:setup:environment` has already been executed
and the e2e/integration test environment is pre-configured. See the Environment
Configuration section in `.specify/memory/constitution.md`. Do not skip e2e tests
citing environment setup during implementation.

## Project Structure

### Documentation (this feature)

```text
specs/017-sbom-converge-failure-semantics/
├── PROBLEM.md           # Originating problem statement (input)
├── spec.md              # Feature specification
├── plan.md              # This file
├── research.md          # Phase 0 output — decisions R1–R8
├── data-model.md        # Phase 1 output — FailureClass, ResolverBreaker, failure/skip records
├── quickstart.md        # Phase 1 output — validation guide
├── contracts/
│   └── README.md        # Output contracts (report format, terminal error, log guarantees)
├── checklists/
│   └── requirements.md
└── tasks.md             # Phase 2 output (/speckit-tasks — NOT created by /speckit-plan)
```

### Source Code (repository root)

```text
pkg/sbom/externalref/
├── model.go             # (touch) FailureClass type if colocated with models
├── service.go           # classification in doResolve; breaker check in Resolve
├── patcher.go           # breaker plumbing through NewExternalRefPatcher
├── enricher.go          # unchanged logic; classified errors flow through
└── *_test.go            # classification + breaker tests (table-driven)

pkg/build/
├── build_phase.go       # convergeSbomByImagesSets: defer report, breaker lifetime, skip logic;
│                        # collectBaseImageSbom: advice gating via purlErrors
├── sbom_step.go         # GOST once-per-process; repo address; timed external-ref section;
│                        # baseSbomMissingError gating support
└── *_test.go            # skip/exit-path/report tests alongside existing purl tests

pkg/oci/artifact/
└── fallback.go          # GetAttached: contextualized multiple-entries warning

test/e2e/sbom/           # e2e scenarios (US1/US2 flows) if extendable within existing suite
```

**Structure Decision**: Monolith CLI tool — all changes land in existing `pkg/sbom/externalref`, `pkg/build`, and `pkg/oci/artifact` files; no command wiring changes in `cmd/werf/`.

## Design Outline

Mapping requirements → design decisions (details in [research.md](./research.md), entities in [data-model.md](./data-model.md)):

1. **Classification (FR-001/002)** — typed `ClassifiedError` produced in `doResolve` where the retryability decision already exists (R1); content failures keep today's aggregation path untouched.
2. **Circuit breaker (FR-003/004)** — `ResolverBreaker` constructed once per build in `convergeSbomByImagesSets`, passed through patcher → service; checked before the retry loop; threshold 5, latched; trips surface as `ErrResolverUnavailable` handled as a hard error in the build phase (R2, R3).
3. **Dependency skipping (FR-005–008)** — `purlErrors` entries become failure/skip records; pre-converge base lookup by `GetBaseImageName()` (same key namespace, verified); transitive root-cause propagation; `baseSbomMissingError` advice gated to bases not processed this run (R4).
4. **Report on every exit path (FR-009)** — `defer` in `convergeSbomByImagesSets`; on hard errors the report is logged and the hard error stays terminal (R5).
5. **Logging (FR-010–014)** — six exact sites confirmed (R6): worker-side error print, advice gating, `sync.Once` GOST warning, contextualized `GetAttached` warning, repo address in `PropagateArtifacts`, timed `LogProcess` around the external-ref patcher.

## Complexity Tracking

> No constitution violations — table intentionally empty.
