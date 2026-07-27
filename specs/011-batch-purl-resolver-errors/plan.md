# Implementation Plan: Batch Purl-Resolver Errors

**Branch**: `fix/sbom/group-purl-resolver-errors` | **Date**: 2026-07-27 | **Spec**: `specs/011-batch-purl-resolver-errors/spec.md`

**Input**: Feature specification from `/specs/011-batch-purl-resolver-errors/spec.md`

## Summary

Currently, PURL resolution operates at two levels:
- **Component level** (`Enricher.Enrich`): resolves PURLs per component within a BOM, logs failures via `logboek` but returns only an aggregated count, losing detail.
- **Image level** (`convergeImageSbom` → `ExternalRefPatcher.Apply`): the first image failure stops the entire build.

This feature:
1. Introduces `ComponentError` type in `pkg/sbom/externalref/` — a proper Go error with `ComponentDetails()` accessor, carrying per-component failure details inline. `logboek.Error()` calls are removed (FR-003, FR-004).
2. Adds sentinel `ErrExternalRefEnrich` in `ExternalRefPatcher.Apply` via `errors.Join(err, ErrExternalRefEnrich)` for reliable detection.
3. Modifies `convergeSbomByImagesSets` to accumulate PURL errors across ALL image sets and return a single aggregated error for the entire build, with hierarchical format: image name → component details.
4. Adds an e2e test at `test/e2e/sbom/purl_resolver_errors_test.go` with a 3-image scenario using `httptest` mock server.

**Detailed error format**:
- Component level: `resolve external references: components failed:\n    - component: <name>: <err>`
- Image level: `  - image: <name>:\n      - component: <name>: <err>`
- Build level: `resolve external references: N of M images failed:\n  - image: <name>:\n      - component: <name>: <err>`

## Technical Context

**Language/Version**: Go 1.24.10

**Primary Dependencies**:
- **SBOM patching**: `pkg/sbom/externalref/` — `ExternalRefPatcher`, `Enricher`, `ComponentError`, `ErrExternalRefEnrich`
- **Parallel execution**: `pkg/util/parallel/` — `DoTasks` (errgroup-based)
- **Error handling**: `errors` (sentinel checks, `Join`, `As`), `fmt.Errorf` (wrapping), `strings.Builder` for structured error formatting
- **Utilities**: `samber/lo` — `lo.Compact` for error aggregation

**Storage**: OCI container registry (Docker v2, ECR) — SBOM artifacts attached to images

**Testing**: Ginkgo + Gomega for unit tests; co-located `*_test.go` files. E2e tests at `test/e2e/sbom/` use Ginkgo + `httptest` mock server.

**Target Platform**: Linux (amd64/arm64) via Buildah

**Project Type**: CLI tool (Go binary via `cmd/werf/main.go`)

### Design Decisions (previously NEEDS CLARIFICATION, now resolved by implementation)

1. **PURL error detection mechanism**: Sentinel `ErrExternalRefEnrich` added in `externalref/patcher.go`. `ExternalRefPatcher.Apply` wraps the enricher error with `fmt.Errorf("enrich external references: %w", err)` and joins with `errors.Join(err, ErrExternalRefEnrich)`, so `errors.Is` reliably detects PURL errors through the chain.

2. **Error propagation boundary**: `convergeSbomByImagesSets` accumulates errors across ALL image sets using a `sync.Map` and returns a single aggregated error via `buildAggregatedPurlError` helper. Non-PURL errors still propagate immediately.

3. **Component-level error format**: `ComponentError` struct with `Error()` returning `"resolve external references: components failed:\n    - component: <name>: <err>"` and `ComponentDetails()` extracting just the details lines. `logboek` calls removed.

4. **E2e test mocking**: Uses `httptest` HTTP mock server returning 404 for specific packages (curl, openssl) and 200 for others (jq). The `Enricher.Resolve` public field enables unit test mocking but the e2e test uses HTTP-level mocking.

## Constitution Check

| Principle | Assessment | Notes |
|-----------|-----------|-------|
| I. Simplicity Over Abstraction | ✅ PASS | `ComponentError` struct with two private fields + 3 methods. `buildAggregatedPurlError` helper function. No interfaces, generics, or embedding. |
| II. Go Idiomatic Code | ✅ PASS | Uses `errors.Is`/`As`, `errors.Join`, `fmt.Errorf`, `strings.Builder`, guard clauses. Public `Resolve` field over getter/setter. |
| III. Minimal Public Surface | ✅ PASS | `ErrExternalRefEnrich` sentinel, public `Resolve` field, and `ComponentError` type (with `ComponentDetails()` for builder) — all justified by cross-package detection and testability. |
| IV. Test-Before-Merge | ⚠️ GATE | `build_phase_purl_test.go` and `enricher_test.go` cover unit tests. `purl_resolver_errors_test.go` covers e2e. Must pass `task test:unit` and `task test:e2e` with label `purl-resolver-errors`. |
| V. Conventional Commits | ✅ PASS | Single commit: `fix(sbom): carry component failure details inline in PURL error text`. |

**Complexity Tracking**: No constitution violations.

## Project Structure

### Documentation (this feature)

```text
specs/011-batch-purl-resolver-errors/
├── spec.md                  # Feature specification
├── plan.md                  # This file
├── research.md              # Design decisions
├── data-model.md            # Entity definitions
├── quickstart.md            # Validation scenarios
├── contracts/               # Interface contracts
├── checklists/              # Feature-specific checklists
└── tasks.md                 # Implementation tasks
```

### Source Code (repository root)

```text
pkg/build/                              # Build phase logic
├── build_phase.go                      # convergeSbomByImagesSets + buildAggregatedPurlError — MODIFIED
├── build_phase_purl_test.go            # Unit tests for PURL error aggregation
├── sbom_step.go                        # Unchanged
│
pkg/sbom/externalref/                   # External reference patcher
├── patcher.go                          # MODIFIED: added ErrExternalRefEnrich sentinel, errors.Join in Apply
├── enricher.go                         # MODIFIED: resolve→Resolve (public), ComponentError type, logboek removed
├── enricher_test.go                    # Tests for component-level error format
│
test/e2e/sbom/                          # E2E tests
├── purl_resolver_errors_test.go        # NEW: 3-image scenario with httptest mock server
├── _fixtures/purl_resolver_errors/     # NEW: werf.yaml, Dockerfile, giterminism config
│
pkg/util/parallel/                      # Parallel execution
├── parallel.go                         # Unchanged
```

## Complexity Tracking

> No constitution violations — skip this section.