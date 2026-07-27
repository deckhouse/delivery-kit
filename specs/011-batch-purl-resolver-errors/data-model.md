# Data Model: Batch Purl-Resolver Errors

## Entities

### Image Set

A group of images at the same dependency level in the build graph, processed sequentially (one set at a time). Within a set, images are processed concurrently via `parallel.DoTasks`.

| Field       | Type         | Description                                                      |
|-------------|--------------|------------------------------------------------------------------|
| `images`    | `[]*Image`   | Images in this set, grouped by name (multi-platform per name)    |
| `names`     | `[]string`   | Unique image names in this set                                   |
| `errors`    | `sync.Map`   | Accumulated PURL errors in `imageName → componentDetails` format |

### Purl Resolution Error (Image Level)

An error that occurs when `ExternalRefPatcher.Apply` fails for a specific image. Detected via `errors.Is(err, externalref.ErrExternalRefEnrich)`. The underlying `ComponentError` is extracted via `errors.As(err, &compErr)` to access component details.

### ComponentError

A Go error type in `pkg/sbom/externalref/` carrying per-component failure details:

```go
type ComponentError struct {
    err     error  // joined inner errors
    details string // per-component failure lines
}

func (e *ComponentError) Error() string   // e.g. "resolve external references: components failed:\n    - component: <name>: <err>\n    ..."
func (e *ComponentError) Unwrap() error
func (e *ComponentError) ComponentDetails() string  // just the per-component lines, no header
```

### Aggregated Build Error

A combined error returned from `buildAggregatedPurlError` helper after all image sets are processed.

**Format**:
```
resolve external references: N of M images failed:
  - image: <name>:
      - component: <name>: <err>
      - component: <name>: <err>
  - image: <name>:
      - component: <name>: <err>
```

Where:
- `N` = count of images with PURL resolution failures
- `M` = total images across all image sets

### Non-PURL Error

Any error from `convergeImageSbom` that is NOT a PURL resolution error. Detected because it does NOT contain `ErrExternalRefEnrich` in the chain. Returned immediately, stopping the build.

Examples:
- `NewExternalRefPatcher` failure (env var missing)
- SBOM scan, merge, or push failure

## State Transitions

### Image Set Processing Flow (Global Aggregation)

```
convergeSbomByImagesSets
  For each image set (sequentially):
    parallel.DoTasks for images in set (concurrently):
      convergeImageSbom(imgName)
        ├─ Success → continue
        ├─ PURL error (errors.Is → ErrExternalRefEnrich):
        │     errors.As → ComponentError
        │     sync.Map.Store(imgName, compErr.ComponentDetails())
        │     return nil  (continue DoTasks)
        └─ Non-PURL error → return immediately (stop build)

    (DoTasks completed for this set, continue to next)

  After all image sets:
    buildAggregatedPurlError(&sync.Map, totalImages)
    ├─ No errors → return nil
    └─ Errors → return "resolve external references: N of M images failed:\n  ..."
```

## Validation Rules

1. All images in a set MUST be attempted for PURL resolution regardless of individual failures (FR-001)
2. Aggregated build error MUST include image name and per-component details for each failed image (FR-002)
3. `ComponentError` MUST carry component failure details in error text AND expose them via `ComponentDetails()` (FR-003)
4. `Enricher.Enrich` MUST NOT use `logboek.Error().LogF(...)` for individual component failures (FR-004)
5. Successful PURL resolution on individual images MUST still produce valid SBOMs (FR-005)
6. Pre-condition failures MUST NOT be aggregated (FR-006)
7. Aggregation MUST be performed once for the ENTIRE build, collecting failures from ALL image sets (FR-007)
8. Empty image sets SHALL be handled without error (FR-008)