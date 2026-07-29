---
title: SBOM E2E Test Strategy
type: decision
sources: [S001]
updated: 2026-07-29
---

## Chosen approach

E2E tests for SBOM PURL resolution use `httptest` to create an HTTP mock server that returns 404 for specific packages (curl, openssl) and 200 for others (jq). Tests run the actual `werf build` command end-to-end, which creates an `ExternalRefPatcher` internally via environment variable (S001).

## Why

- Validates the full build pipeline — from `werf build` invocation through `ExternalRefPatcher.Apply` to `convergeSbomByImagesSets` error aggregation — at the HTTP protocol level.
- The 3-image fixture (`test/e2e/sbom/_fixtures/purl_resolver_errors/`) exercises partial and total failure scenarios in a single test.

## Unit test counterpart

`Enricher.Resolve` is a public function field specifically to enable direct mocking in unit tests (via `enricher_test.go`). The e2e test complements this by testing at the HTTP level rather than mocking `Resolve` directly (S001).

See also: [ComponentError type](./component-error-type.md).