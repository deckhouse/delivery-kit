---
title: PURL Error Aggregation Strategy
type: decision
sources: [S001]
updated: 2026-08-17
---

## Chosen approach

`convergeSbomByImagesSets` in `pkg/build/` accumulates PURL failures across **all** image sets using a `sync.Map` (storing `imageName → purlFailureRecord`). A helper function `buildAggregatedPurlError` iterates the map, formats the failures hierarchically, and returns a single aggregated error at the end (S001).

A `purlFailureRecord` is either a **direct failure** (`rootImage` equals the image's own name; carries component-level details from `ComponentError.ComponentDetails()`) or a **skip record** (`rootImage` points at the root-cause image). Any image whose record is present is treated as "SBOM not generated in this run": dependents — via `fromImage` (`GetBaseImageName()`) or internal `import` sources (`GetImportImagesInfo()`) — are skipped before converge with the root cause propagated transitively (A → B → C reports A). The same gate guards both `collectBaseImageSbom` and `collectImportImageSboms` (`dependencyPurlFailureError`).

## Why

- The function already owns the `parallel.DoTasks` calls and iterates over all image sets — accumulating at this level is the natural integration point.
- A single aggregated error is cleaner for consumers than handling N separate errors from N image sets.
- Non-PURL errors from `parallel.DoTasks` still propagate immediately (not aggregated) — with one exception: a resolver circuit-breaker trip (`ErrResolverUnavailable`) is checked **before** the `ErrExternalRefEnrich` defer branch, because `ExternalRefPatcher.Apply` wraps every enrich failure (including trips) with the enrich sentinel.

## Guarantees

- The aggregated report is emitted on **every** exit path of `convergeSbomByImagesSets`: on the happy path it is the returned error; on a hard error (including a breaker trip) it is logged via `logboek` before the hard error propagates, and the hard error stays terminal.
- A breaker trip is canonicalized via `ResolverBreaker.UnavailableError()` so exactly one resolver-unavailable error naming the endpoint surfaces per build, regardless of how many parallel workers observed the trip.

## Hierarchical error format

```
resolve external references: N of M images failed:
  - image: <name>:
    - component: <name>: resolve "purl": ...: unexpected status 404
  - image: <dependent-name>:
    - skipped: SBOM for image "<root-name>" was not generated: <root cause>
```

The format has three levels: component details (or a skip line), grouped under image name, headed by a summary line; N counts direct failures plus skipped images (S001).

See also: [PURL resolution](./purl-resolution.md), [ComponentError type](./component-error-type.md).