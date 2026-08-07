---
title: PURL Retry Parameters
type: decision
sources: [S014]
updated: 2026-08-07
---

## Chosen approach

Reduce the PURL resolution retry budget from 30 s to 10 s (`MaxElapsedTime`) and lower the HTTP client timeout from 30 s to 5 s. The exponential backoff parameters (`InitialInterval`: 500 ms, `Multiplier`: 1.5, `MaxInterval`: 60 s) are left at their library defaults (S014).

## Why

- A 30 s retry budget makes `werf sbom` stall for tens of seconds when the PURL resolution service is slow or unavailable. CI/CD pipelines are sensitive to total runtime and benefit from failing fast.
- The HTTP client timeout was also 30 s, meaning a single hung request could consume the entire retry budget with no retries attempted. Lowering it to 5 s leaves room for up to about 2 retries within the new 10 s budget.

## Alternatives considered

- **10 s HTTP timeout** (same as retry budget) — would leave zero room for retries, defeating the purpose of having a retry mechanism (S014).
- **Making all parameters configurable via `ServiceConfig`** — not needed; the spec explicitly preserves the existing strategy (S014).
- **Custom backoff multiplier** — no requirement for this; library defaults are reasonable for a network service (S014).

## No API changes

`ServiceConfig` and `Service` public API are unchanged. Callers that pass a custom `HTTPClient` (e.g. the test `"returns error on server error (without retry)"`) are unaffected (S014).

See also: [PURL resolution](./purl-resolution.md).