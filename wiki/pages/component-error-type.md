---
title: ComponentError Type
type: component
sources: [S001]
updated: 2026-07-29
---

`ComponentError` is a structured Go error type in `pkg/sbom/externalref/` that carries per-component PURL resolution failure details inline.

## Structure

- Two private fields: `err` (joined inner errors via `errors.Join`) and `details` (per-component lines).
- `Error()` returns: `"resolve external references: components failed:\n    - component: <name>: <err>\n"`
- `ComponentDetails()` returns just the per-component lines (without the header), used by the build-level aggregation.
- `Unwrap()` returns the joined inner errors for `errors.Is`/`errors.As` traversal.

## Design decisions

- Carries failure details in the error text instead of logging them via `logboek` — removing the dual source of truth between log output and error text (S001).
- Private fields with public accessors keep the error surface small while enabling structured access for `buildAggregatedPurlError` to format the hierarchical build-level error (S001).

See also: [PURL resolution](./purl-resolution.md), [error aggregation strategy](./error-aggregation-strategy.md).