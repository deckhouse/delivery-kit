---
title: PURL Error Aggregation Strategy
type: decision
sources: [S001]
updated: 2026-07-29
---

## Chosen approach

`convergeSbomByImagesSets` in `pkg/build/` accumulates PURL errors across **all** image sets using a `sync.Map` (storing `imageName → componentDetailsString`). A helper function `buildAggregatedPurlError` iterates the map, formats the errors hierarchically, and returns a single aggregated error at the end (S001).

## Why

- The function already owns the `parallel.DoTasks` calls and iterates over all image sets — accumulating at this level is the natural integration point.
- A single aggregated error is cleaner for consumers than handling N separate errors from N image sets.
- Non-PURL errors from `parallel.DoTasks` still propagate immediately (not aggregated).

## Hierarchical error format

```
resolve external references: N of M images failed:
  - image: <name>:
      - component: <name>: resolve "purl": ...: unexpected status 404
```

The format has three levels: component details, grouped under image name, headed by a summary line (S001).

See also: [PURL resolution](./purl-resolution.md), [ComponentError type](./component-error-type.md).