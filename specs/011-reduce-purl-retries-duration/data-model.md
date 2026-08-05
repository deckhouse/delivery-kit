# Data Model: Reduce PURL Resolver Retries Duration

## Overview

This feature does not introduce new entities or modify existing data structures. It only changes configuration constants within the existing `Service` type. This document records the current model for reference.

## Entities

### ExternalRef Service

The `Service` type (in `pkg/sbom/externalref/service.go`) is an HTTP client that communicates with a PURL resolution service, managing request timeouts and retry logic.

```
Service
├── serverURL: string          — Base URL of the PURL resolution service
└── httpClient: *http.Client   — HTTP client with configurable timeout
```

**Configuration** (`ServiceConfig`):
| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `ServerURL` | `string` | — (required) | Base URL of the resolution service |
| `Timeout` | `time.Duration` | 30 s → **5 s** 🎯 | HTTP client timeout |
| `HTTPClient` | `*http.Client` | nil (auto-created) | Custom HTTP client (overrides Timeout) |

### Retry Parameters (exponential backoff via `cenkalti/backoff/v5`)

| Parameter | Current Value | Target Value 🎯 | Description |
|-----------|--------------|-----------------|-------------|
| `InitialInterval` | 500 ms (default) | unchanged | Initial retry delay |
| `Multiplier` | 1.5 (default) | unchanged | Backoff multiplier |
| `MaxInterval` | 60 s (default) | unchanged | Maximum retry delay |
| `MaxElapsedTime` | 30 s | **10 s** 🎯 | Total retry budget |

### Enricher

The `Enricher` type (in `pkg/sbom/externalref/enricher.go`) orchestrates parallel PURL resolution for SBOM components. It is **unaffected** by this change.

```
Enricher
├── resolve: func(ctx, purl) → (*ResolveResult, error)  — Injected resolver function
└── Enrich(ctx, *cdx.BOM) → error                       — Parallel enrichment
```

### ResolveResult (response data model)

Defined in `model.go` — **unchanged** by this feature.

```
ResolveResult
├── PURL: string
├── PURLRequested: string
├── URL: string
├── Kind: string
├── Confirmed: bool
├── Status: string
├── Confidence: float64
├── Provider: string
├── Resolution: string
└── Sources: []Source
    └── Source
        ├── Kind: string
        ├── Meta: SourceMeta
        │   ├── HTTPStatus: int
        │   └── RequestURL: string
        ├── Provider: string
        └── PickedURL: string
```

## Validation Rules

- `MaxElapsedTime` must be greater than `InitialInterval` (10 s > 500 ms ✅)
- `MaxElapsedTime` must be greater than `http.Client.Timeout` (10 s > 5 s ✅) — allows at least 1 retry
- `http.Client.Timeout` must be less than `MaxElapsedTime` (5 s < 10 s ✅) — prevents hung request from consuming entire budget

## State Transitions

No state transitions apply. The `Service.Resolve` method performs a stateless HTTP request with retry:

```
Resolve(purl)
  └─> Exponential backoff retry loop (max 10 s)
       ├─> HTTP GET request (timeout: 5 s)
       │    ├─> 200 OK → parse response → return result
       │    ├─> 429/5xx → retry (if budget remains)
       │    └─> 400/404 → permanent error (no retry)
       └─> Budget exhausted → return last error
```