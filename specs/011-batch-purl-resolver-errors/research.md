# Research: Batch Purl-Resolver Errors

## Overview

Design decisions resolved during implementation of the feature.

## 1. PURL Error Detection Mechanism

**Decision**: Sentinel `ErrExternalRefEnrich` in `externalref/patcher.go`, joined into the error chain via `errors.Join(err, ErrExternalRefEnrich)` in `ExternalRefPatcher.Apply`.

**Rationale**:
- `ExternalRefPatcher.Apply` wraps the enricher error with `fmt.Errorf("enrich external references: %w", err)` (existing behavior) AND joins with `errors.Join(err, ErrExternalRefEnrich)` so `errors.Is` reliably detects PURL errors.
- The sentinel appears in the chain regardless of how many wrapping layers `convergeImageSbom` adds.
- `errors.Is` traverses the chain reliably.

**Alternatives considered**:
- String matching: rejected — less robust.
- Only wrapping without join: rejected — the join ensures the sentinel is on the chain even after the enricher error restructures.

## 2. Error Propagation Boundary

**Decision**: `convergeSbomByImagesSets` accumulates PURL errors across ALL image sets using a `sync.Map`, then returns a single aggregated error via `buildAggregatedPurlError` helper function.

**Rationale**:
- `convergeSbomByImagesSets` owns the `parallel.DoTasks` calls and iterates over all image sets.
- `sync.Map` stores `imageName → componentDetailsString` per failed image.
- `buildAggregatedPurlError` iterates the map, formats hierarchically, and returns a single error once at the end.
- Non-PURL errors from `parallel.DoTasks` still propagate immediately.

## 3. Component-Level Error Format

**Decision**: `*ComponentError` struct with `Error()` returning structured text and `ComponentDetails()` returning just the details lines.

**Key design**:
- `ComponentError` has `err` (joined inner errors) and `details` (per-component lines) — both private.
- `Error()`: `"resolve external references: components failed:\n    - component: <name>: <err>\n"`
- `ComponentDetails()`: returns only per-component lines (without header) for build-level aggregation.
- `Unwrap()`: returns the joined inner errors.
- `logboek.Error().LogF(...)` calls in `Enricher.Enrich` are removed — the error text is the sole carrier.

**Error chain example**:
```
resolve external references: 2 of 3 images failed:
  - image: image-fail-all:
      - component: curl: resolve "pkg:generic/curl@8.12.1": ...: unexpected status 404
      - component: openssl: resolve "pkg:generic/openssl@3.6.2": ...: unexpected status 404
  - image: image-fail-partial:
      - component: curl: resolve "pkg:generic/curl@8.12.1": ...: unexpected status 404
```

## 4. E2E Test Mocking

**Decision**: `httptest` HTTP mock server returning 404 for specific packages (curl, openssl) and 200 for jq.

**Rationale**:
- The e2e test runs the actual `werf build` command end-to-end, which creates an `ExternalRefPatcher` internally via environment variable.
- `httptest` simulates the external ref server at the HTTP protocol level.
- `Enricher.Resolve` is public for unit test mocking (enricher_test.go), but the e2e test works at the HTTP level to validate the full build pipeline.
- Test fixture at `test/e2e/sbom/_fixtures/purl_resolver_errors/werf.yaml` defines 3 images with specific PM packages.

## Design Decisions Summary

| Decision | Choice | Key Alternative Rejected |
|----------|--------|-------------------------|
| Error detection | Sentinel `ErrExternalRefEnrich` + `errors.Join` | String matching (fragile) |
| Error boundary | `convergeSbomByImagesSets` after all sets via `sync.Map` | Per-set return (would produce multiple errors) |
| Component error type | `*ComponentError` struct with `Error()` + `ComponentDetails()` | Plain string (loss of structured access) |
| Component failure carrier | Error text replaces `logboek` | Logging + error (dual source of truth) |
| E2e mock approach | `httptest` HTTP mock server | Direct `Resolve` mock at e2e level (not a full pipeline test) |
| Aggregation scope | Global — all image sets, single error | Per image set (would produce N errors for N sets) |
| Pre-condition handling | Covered by FR-006 | — |
| Empty set | Covered by FR-008 | — |