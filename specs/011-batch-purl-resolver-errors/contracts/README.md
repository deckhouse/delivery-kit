# Contracts: Batch Purl-Resolver Errors

## Internal Contract: Build Phase → ExternalRefPatcher

### Error Contract

`convergeSbomByImagesSets` in `pkg/build/build_phase.go` relies on the following error contract:

- **PURL resolution errors**: `ExternalRefPatcher.Apply` returns errors whose chain contains `ErrExternalRefEnrich` (via `errors.Join`). The underlying `*ComponentError` is extracted via `errors.As`. Detection: `errors.Is(err, externalref.ErrExternalRefEnrich)`.
- **Pre-condition errors**: `NewExternalRefPatcher` returns errors without `ErrExternalRefEnrich` in the chain. Propagated immediately.

### Sentinel Error

Defined in `pkg/sbom/externalref/patcher.go`:

```go
var ErrExternalRefEnrich = errors.New("enrich external references")
```

Used in `ExternalRefPatcher.Apply`:

```go
func (p *ExternalRefPatcher) Apply(ctx context.Context, bom *cdx.BOM) (*cdx.BOM, error) {
    if err := p.enricher.Enrich(ctx, bom); err != nil {
        return bom, fmt.Errorf("enrich external references: %w", errors.Join(err, ErrExternalRefEnrich))
    }
    return bom, nil
}
```

### ComponentError Type

Defined in `pkg/sbom/externalref/enricher.go`:

```go
type ComponentError struct { /* ... */ }

func (e *ComponentError) Error() string
func (e *ComponentError) Unwrap() error
func (e *ComponentError) ComponentDetails() string  // per-component lines without header
```

- `ComponentDetails()` returns only per-component failure lines (e.g., `    - component: curl: resolve "pkg:generic/curl@8.12.1": unexpected status 404`), without the header.
- The build phase uses `errors.As(err, &compErr)` to extract it and calls `compErr.ComponentDetails()` for hierarchical aggregation.

### Enricher Public Resolve Field

```go
type Enricher struct {
    Resolve func(ctx context.Context, purl string) (*ResolveResult, error)
}
```

- Renamed from private `resolve` to public `Resolve` for unit test mocking.
- E2e tests (`test/e2e/sbom/purl_resolver_errors_test.go`) use `httptest` HTTP mock server at the HTTP protocol level (not direct `Resolve` injection).

### Interface: BOMPatcherInterface

Defined in `pkg/build/sbom_step.go`:

```go
type BOMPatcherInterface interface {
    Apply(ctx context.Context, bom *cdx.BOM) (*cdx.BOM, error)
}
```

### Internal Contract: convergeSbomByImagesSets → buildAggregatedPurlError

| Return Value | Source | Effect on Build |
|-------------|--------|-----------------|
| `nil` | All images processed, no PURL failures | Build continues |
| `error` (non-PURL) | Pre-condition / scan / merge / push failure | Stops build immediately |
| Aggregated error | `buildAggregatedPurlError` after all sets | Stops build with single hierarchical error |