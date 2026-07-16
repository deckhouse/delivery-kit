# Implementation Plan: Collect External Reference Errors

**Branch**: `feat/sbom/collect-external-ref-errors` | **Date**: 2026-07-16 | **Spec**: `specs/004-sbom-collect-external-ref-errors/spec.md`

**Input**: Reverse-engineered from existing code in `pkg/sbom/externalref/` (branch `feat/sbom/collect-external-ref-errors`)

## Summary

Change the SBOM external reference enricher to collect all component enrichment failures instead of stopping at the first one. This involves replacing `errgroup.WithContext(ctx)` (which cancels on first error) with a plain `errgroup.Group`, collecting errors in a shared slice, and returning a single aggregated error message with the count of failures.

## Technical Context

**Language/Version**: Go 1.24.10

**Primary Dependencies**:
- **SBOM**: `CycloneDX/cyclonedx-go`
- **Utilities**: `samber/lo`, `golang.org/x/sync/errgroup`, `github.com/werf/logboek`
- **Concurrency**: `errgroup.Group` with `SetLimit(10)`, `sync.Map` for deduplication

**Storage**: None (in-memory enrichment)

**Testing**: Ginkgo + Gomega unit tests co-located with source; `httptest.Server` for service mocking

**Target Platform**: Linux (amd64/arm64); part of `werf` CLI

## Project Structure

### Source Code

```text
pkg/sbom/externalref/
├── enricher.go              # Core enrichment logic (changed)
├── enricher_test.go         # Unit tests for Enricher (changed)
├── patcher.go               # ExternalRefPatcher wrapper (unchanged)
├── service.go               # HTTP resolve service (unchanged)
├── model.go                 # ResolveResult, Source types (unchanged)
├── helpers_test.go          # Test helpers (unchanged)
├── suite_test.go            # Ginkgo suite setup (unchanged)
├── service_test.go          # Service tests (unchanged)
└── integration_test.go      # Integration tests (unchanged)
```

## Complexity Assessment

| Metric | Value |
|--------|-------|
| Files changed | 2 (enricher.go, enricher_test.go) |
| Lines changed | +77 / -43 |
| New types | 0 external, 1 internal (`componentError`) |
| New functions | 1 internal (`enrichComponent`) |
| Concurrency change | `errgroup.WithContext` → plain `errgroup.Group` |

**Complexity**: Low — focused, well-scoped behavioural change within a single package. The change primarily involves error handling semantics and concurrency control.

## Implementation Approach

1. **Extract per-component logic** into `enrichComponent(ctx, comp, seen)` method — moves the existing inline per-component enrichment into a named method that returns an error instead of failing the entire errgroup
2. **Change errgroup** from `WithContext(ctx)` (first-error-cancels) to a plain `Group` (all-goroutines-continue) — this is the key behavioural change
3. **Collect errors** in a `[]*componentError` slice indexed by component position, populated when `enrichComponent` returns non-nil
4. **Await completion** with `_ = g.Wait()` (discarding the group-level error since errors are collected individually)
5. **Aggregate and report**: use `lo.Compact` to filter out nil entries, log each failure via `logboek.Error`, return `fmt.Errorf("resolve external references: %d of %d components failed", ...)`
6. **Update tests** to match new error messages and add coverage for multi-failure scenarios