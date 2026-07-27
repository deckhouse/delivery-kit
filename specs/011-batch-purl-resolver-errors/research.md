# Research: Batch Purl-Resolver Errors

## Overview

Research findings to resolve all "NEEDS CLARIFICATION" items from the Technical Context of `plan.md`.

## 1. PURL Error Detection Mechanism

**Decision**: Define a sentinel `var ErrExternalRefEnrich = errors.New("enrich external references")` in `pkg/sbom/externalref/patcher.go` and detect it via `errors.Is(err, externalref.ErrExternalRefEnrich)` in the `convergeSbomByImagesSets` closure.

**Rationale**:
- `ExternalRefPatcher.Apply` wraps the underlying error with `fmt.Errorf("enrich external references: %w", err)`, making the sentinel part of the error chain.
- `errors.Is` traverses the chain reliably regardless of how many wrapping layers `convergeImageSbom` adds.
- This is the idiomatic Go approach for cross-package error detection.
- The sentinel is added to the existing `externalref` package, which already owns the `ExternalRefPatcher` type — the error is co-located with its source.

**Alternatives considered**:
- String matching (`strings.Contains`): rejected per design review — less robust, more fragile.
- Detecting in `sbom_step.go` or `convergeImageSbom` via a custom error type: rejected — adds detection at the wrong abstraction level, caller would still need to distinguish.

## 2. Error Propagation Boundary

**Decision**: Aggregated error is returned from `convergeSbomByImagesSets` after ALL image sets are processed.

**Rationale**:
- `convergeSbomByImagesSets` owns the `parallel.DoTasks` calls and iterates over all image sets.
- It accumulates PURL errors across all sets and returns a single aggregated error once at the end.
- The caller does not need to know about PURL resolution internals.
- No changes needed outside `pkg/build/build_phase.go`.

## Design Decisions Summary

| Decision | Choice | Key Alternative Rejected |
|----------|--------|-------------------------|
| Error detection | Sentinel `ErrExternalRefEnrich` + `errors.Is` | String matching (fragile) |
| Error boundary | `convergeSbomByImagesSets` after all sets | Per-set return (would produce multiple errors) |
| Aggregation scope | Global — all image sets, single error | Per image set (would produce N errors for N sets) |
| Pre-condition handling | Covered by FR-005 — no special handling needed | - |
| Empty set | Covered by FR-007 — no special handling needed | - |