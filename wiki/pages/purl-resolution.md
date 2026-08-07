---
title: PURL Resolution in werf
type: concept
sources: [S001, S014]
updated: 2026-08-07
---

werf resolves PURLs during SBOM processing to attach external references to software bills of materials. The resolution pipeline has three tiers:

- **Component tier** (`Enricher` in `pkg/sbom/externalref/`): resolves PURLs for individual components within a BOM. Calls a configurable `Resolve` function for each component. Failure details are captured into a `ComponentError` and carried inline in the error text rather than logged separately (S001).
- **Image tier** (`ExternalRefPatcher` in `pkg/sbom/externalref/`): applies enrichment results to each image's SBOM. Wraps the enricher error with `fmt.Errorf` and joins a sentinel `ErrExternalRefEnrich` via `errors.Join` so consumers can detect PURL failures through any number of wrapping layers (S001).
- **Build tier** (`convergeSbomByImagesSets` in `pkg/build/`): orchestrates across all image sets. Accumulates PURL errors using a `sync.Map` (keyed by image name) and returns a single aggregated error via `buildAggregatedPurlError` for the entire build (S001).

Previously, component-level failures were logged via `logboek` with only an aggregated count returned, losing per-component detail. The first image failure stopped the entire build. The current design carries structured detail through the error chain and aggregates across all image sets before failing.

Each PURL resolution is handled by the **ExternalRef Service** (`pkg/sbom/externalref/service.go`), an HTTP client that retries failed requests with exponential backoff via `cenkalti/backoff/v5`. The retry budget is 10 s total (`MaxElapsedTime`), with an HTTP request timeout of 5 s per attempt, allowing up to about 2 retries before exhaustion. The backoff parameters (`InitialInterval`: 500 ms, `Multiplier`: 1.5, `MaxInterval`: 60 s) use the library defaults (S014).

See also: [ComponentError type](./component-error-type.md), [error detection sentinel](./error-detection-sentinel.md), [error aggregation strategy](./error-aggregation-strategy.md), [PURL retry parameters](./purl-retry-parameters.md), [SBOM cache invalidation](./sbom-cache-invalidation.md), [SBOM e2e test strategy](./sbom-e2e-test-strategy.md).