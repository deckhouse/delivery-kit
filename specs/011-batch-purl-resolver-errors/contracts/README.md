# Contracts: Batch Purl-Resolver Errors

## Internal Contract: Build Phase → ExternalRefPatcher

### Error Contract

The `convergeSbomByImagesSets` method in `pkg/build/build_phase.go` relies on the following error contract from the `ExternalRefPatcher`:

- **PURL resolution errors**: `ExternalRefPatcher.Apply` returns errors wrapping the sentinel `externalref.ErrExternalRefEnrich`. These are detected by the caller via `errors.Is(err, externalref.ErrExternalRefEnrich)` and accumulated globally across all image sets rather than propagated immediately.
- **Pre-condition errors**: `NewExternalRefPatcher` returns errors that are not `ErrExternalRefEnrich`. These are propagated immediately.

### Sentinel Error

Defined in `pkg/sbom/externalref/patcher.go`:

```go
var ErrExternalRefEnrich = errors.New("enrich external references")
```

Wrapped by `ExternalRefPatcher.Apply`:

```go
func (p *ExternalRefPatcher) Apply(ctx context.Context, bom *cdx.BOM) (*cdx.BOM, error) {
    if err := p.enricher.Enrich(ctx, bom); err != nil {
        return bom, fmt.Errorf("enrich external references: %w", err)
    }
    return bom, nil
}
```

### Interface: BOMPatcherInterface

Defined in `pkg/build/sbom_step.go`:

```go
type BOMPatcherInterface interface {
    Apply(ctx context.Context, bom *cdx.BOM) (*cdx.BOM, error)
}
```

- `ExternalRefPatcher` implements this interface.
- The `Apply` method receives the current BOM and returns the patched BOM and an error.
- On error, the error wraps `ErrExternalRefEnrich` via `fmt.Errorf("enrich external references: %w", err)`.

### Internal Contract: convergeSbomByImagesSets

PURL resolution errors are accumulated globally across all image sets. The function returns a single aggregated error once after ALL image sets have been processed:

| Return Value | Meaning | Effect on Build |
|-------------|---------|-----------------|
| `nil` | All images processed, no PURL failures | Build continues |
| `error` (non-PURL) | Non-retryable failure in a set | Stops build immediately |
| Aggregated error (after all sets) | PURL failures across one or more image sets | Stops build with single aggregated error |