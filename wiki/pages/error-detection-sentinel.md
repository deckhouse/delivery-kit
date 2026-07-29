---
title: PURL Error Detection via Sentinel
type: decision
sources: [S001]
updated: 2026-07-29
---

## Chosen approach

Add a sentinel error `ErrExternalRefEnrich` in `pkg/sbom/externalref/patcher.go`. `ExternalRefPatcher.Apply` wraps the enricher error with `fmt.Errorf("enrich external references: %w", err)` (existing behavior) **and** joins with `errors.Join(err, ErrExternalRefEnrich)` so `errors.Is` reliably detects PURL failures through any number of wrapping layers (S001).

## Why

- `errors.Is` traverses the chain reliably regardless of how many wrapping layers `convergeImageSbom` adds.
- The sentinel appears in the chain even if the enricher error gets restructured.

## Alternatives rejected

- **String matching**: rejected as fragile against message changes.
- **Only wrapping without `errors.Join`**: rejected because the join ensures the sentinel stays on the chain even after the enricher error's internal structure changes (S001).

See also: [PURL resolution](./purl-resolution.md), [ComponentError type](./component-error-type.md).