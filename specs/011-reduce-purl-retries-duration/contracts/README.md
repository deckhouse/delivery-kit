# Contracts: Reduce PURL Resolver Retries Duration

## Overview

This feature changes internal configuration constants in the `pkg/sbom/externalref` package. No new public contracts are introduced. This document records the existing public API contracts for reference.

## ServiceConfig Contract

The `ServiceConfig` struct is the public API for constructing a `Service`:

```go
type ServiceConfig struct {
    ServerURL  string
    Timeout    time.Duration
    HTTPClient *http.Client
}
```

**Contract rules**:
- `ServerURL` is required (non-empty). Leading/trailing slashes are stripped.
- `Timeout` defaults to 30 s (will become **5 s**). Applied only when `HTTPClient` is nil.
- `HTTPClient` overrides `Timeout` when set. If nil, an HTTP client is auto-created with the configured `Timeout`.
- All fields are optional except `ServerURL`.

## Service.Resolve Contract

```go
func (s *Service) Resolve(ctx context.Context, purl string) (*ResolveResult, error)
```

**Contract rules**:
- `ctx` is required. Must be the first argument.
- `purl` is required. Non-empty URL-encoded PURL string.
- Returns `(*ResolveResult, nil)` on success.
- Returns `(nil, error)` on failure, with retry:
  - HTTP 429 or 5xx → retry (up to `MaxElapsedTime` budget)
  - HTTP 4xx (other than 429) → permanent error, no retry
  - Network/transport errors → retry
  - JSON parse errors → permanent error
  - Empty URL in response → permanent error
- Maximum retry duration: **10 s** (was 30 s).
- HTTP request timeout: **5 s** (was 30 s).

## Enricher.Enrich Contract

```go
func (e *Enricher) Enrich(ctx context.Context, bom *cdx.BOM) error
```

**Contract rules**:
- `ctx` is required. Must be the first argument.
- `bom` is required. If nil or nil components, returns nil (no-op).
- Runs up to 10 concurrent resolutions via `errgroup`.
- Collects all errors and returns an aggregated error.
- Sets `ExternalReferences` at both component and BOM level.
- Unchanged by this feature.

## ExternalRefPatcher Contract

```go
func NewExternalRefPatcher() (*ExternalRefPatcher, error)
func (p *ExternalRefPatcher) Apply(ctx context.Context, bom *cdx.BOM) (*cdx.BOM, error)
```

**Contract rules**:
- `NewExternalRefPatcher` reads `WERF_EXTERNAL_REFS_SERVER_URL` env var. Returns error if unset.
- Creates a `Service` with default `ServiceConfig` — will inherit the new **5 s** timeout.
- `Apply` delegates to `Enricher.Enrich` and returns the original BOM on error.
- Unchanged by this feature (inherits new defaults).