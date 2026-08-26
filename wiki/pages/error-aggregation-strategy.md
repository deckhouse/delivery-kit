---
title: PURL Error Aggregation Strategy
type: decision
sources: [S001]
updated: 2026-08-17
---

## Chosen approach

`pkg/sbom/convergefailure` owns the failure semantics of an SBOM converge run; `convergeSbomByImagesSets` in `pkg/build/` only orchestrates it. A `Tracker` created per build accumulates failures across **all** image sets (an image-name-keyed `sync.Map` of `Record`), and `Tracker.AggregatedError` renders them hierarchically into a single error (S001).

A `Record` is either a **direct failure** (`RootImage` equals the image's own name; carries component-level details from `ComponentError.ComponentDetails()`) or a **skip record** (`RootImage` points at the root-cause image). Any image with a record is treated as "SBOM not generated in this run": dependents — via `fromImage` or internal `import` sources, collected by `DependencyImageNames` — are skipped by `Tracker.SkipDependent` before converge, with the root cause propagated transitively (A → B → C reports A). The same store answers `Tracker.DependencyError`, which guards both `collectBaseImageSbom` and `collectImportImageSboms`.

## Why

- One package owns the whole contract, so a change to failure semantics (a new dependency kind, a new failure class, a report change) is made once and applies to every consumer; the import-dependency gap existed while base and import paths were handled separately.
- A single aggregated error is cleaner for consumers than handling N separate errors from N image sets.
- Non-PURL errors from `parallel.DoTasks` still propagate immediately (not aggregated) — with one exception: a resolver circuit-breaker trip (`ErrResolverUnavailable`) is checked **before** the `ErrExternalRefEnrich` defer branch, because `ExternalRefPatcher.Apply` wraps every enrich failure (including trips) with the enrich sentinel.

## Guarantees

- `Tracker.Finish` emits the aggregated report on **every** exit path: on the happy path it is the returned error; on a hard error (including a breaker trip) it is logged via `logboek` before the hard error propagates, and the hard error stays terminal.
- A breaker trip is canonicalized via `ResolverBreaker.UnavailableError()` so exactly one resolver-unavailable error naming the endpoint surfaces per build, regardless of how many parallel workers observed the trip.

## Hierarchical error format

```
resolve external references: N of M images failed:
  - image: <name>:
    - component: <name> (<purl>): resolve: unexpected status 404
  - image: <dependent-name>:
    - skipped: SBOM for image "<root-name>" was not generated: <root cause>
```

The format has three levels: component details (or a skip line), grouped under image name, headed by a summary line; N counts direct failures plus skipped images (S001). The purl is rendered once, by the enricher, so every component failure carries it regardless of which layer produced the error; components legitimately without a purl (see `purlNotExpected`) fall back to `- component: <name>: <error>`.

See also: [PURL resolution](./purl-resolution.md), [ComponentError type](./component-error-type.md).