# Data Model: Batch Purl-Resolver Errors

## Entities

### Image Set

A group of images at the same dependency level in the build graph, processed sequentially (one set at a time). Within a set, images are processed concurrently via `parallel.DoTasks`.

| Field       | Type       | Description                                                      |
|-------------|------------|------------------------------------------------------------------|
| `images`    | `[]*Image` | Images in this set, grouped by name (multi-platform per name)    |
| `names`     | `[]string` | Unique image names in this set                                   |
| `errors`    | `[]purlError` | Accumulated PURL resolution errors for this set (runtime only)   |

### Purl Resolution Error

An error that occurs when the `ExternalRefPatcher.Apply` method fails to enrich a component's PURL with external references for a specific image.

| Field       | Type       | Description                                                    |
|-------------|------------|----------------------------------------------------------------|
| `imageName` | `string`   | Name of the image that failed PURL resolution                  |
| `err`       | `error`    | The underlying error from `ExternalRefPatcher.Apply`           |

Detection: `errors.Is(err, externalref.ErrExternalRefEnrich)` — the sentinel is defined in `pkg/sbom/externalref/` and wrapped by `ExternalRefPatcher.Apply` via `fmt.Errorf("enrich external references: %w", err)`.

### Aggregated Build Error

A combined error that collects all PURL resolution failures from all images across ALL image sets and presents them as a single error message for the entire build.

**Format**: `"resolve external references: N of M images failed"`

Where:
- `N` = count of images with PURL resolution failures across all image sets
- `M` = total images across all image sets

### Non-PURL Error

Any error from `convergeImageSbom` that is NOT a PURL resolution error. These are returned as-is and stop the current image set immediately, preventing further sets from being processed.

Examples:
- `NewExternalRefPatcher` failure (env var missing)
- Base image collection failure (`collectBaseImageSbom`)
- SBOM scan failure (`GenerateSBOM`)
- SBOM merge failure (`MergeBOMs`)
- SBOM push failure (`PushSBOM`)

## State Transitions

### Image Set Processing Flow (Global Aggregation)

```
┌──────────────────────────────────────────────────────────────────────┐
│  convergeSbomByImagesSets                                            │
│  ┌──────────────────────────────────────────────────────────────────┐│
│  │  For each image set in sequence:                                 ││
│  │  ┌────────────────────────────────────────────────────────────┐  ││
│  │  │  parallel.DoTasks for images in set:                       │  ││
│  │  │  ┌──────────────────────────────────────────────────────┐  │  ││
│  │  │  │  convergeImageSbom(imgName)                          │  │  ││
│  │  │  │  ├─ Success → continue                                │  │  ││
│  │  │  │  ├─ PURL error → accumulate to global collector       │  │  ││
│  │  │  │  └─ Non-PURL error → return immediately (stop build)  │  │  ││
│  │  │  └──────────────────────────────────────────────────────┘  │  ││
│  │  └────────────────────────────────────────────────────────────┘  ││
│  │                                                                   ││
│  │  Next Image Set (continue accumulating)  ──────────────────────→  ││
│  └──────────────────────────────────────────────────────────────────┘│
│                                                                       │
│  After all image sets processed:                                      │
│  ├─ No PURL errors → return nil                                       │
│  └─ PURL errors → return single aggregated error for entire build     │
└──────────────────────────────────────────────────────────────────────┘
```

## Error Type Distinctions

| Error Category | Source | Detection | Stop Build? | Behavior |
|---------------|--------|-----------|-------------|----------|
| PURL resolution | `ExternalRefPatcher.Apply` | `errors.Is("ErrExternalRefEnrich")` | After all image sets | Accumulated globally, single aggregated error |
| Pre-condition | `NewExternalRefPatcher` | Not an `ErrExternalRefEnrich` error | Immediately | Returned as-is from `convergeImageSbom` |
| Other SBOM error | `convergeImageSbom` (scan, merge, push) | Not an `ErrExternalRefEnrich` error | Immediately | Returned as-is from `convergeImageSbom` |

## Validation Rules

1. All images in a set MUST be attempted for PURL resolution regardless of individual failures (FR-001)
2. Aggregated error MUST use format `"resolve external references: N of M images failed"` covering ALL image sets (FR-002)
3. Successful PURL resolution on individual images MUST still produce valid SBOMs (FR-003)
4. Pre-condition failures MUST NOT be aggregated (FR-004)
5. Aggregation MUST be performed once for the ENTIRE build, collecting failures from ALL image sets (FR-005)
6. Empty image sets SHALL be handled without error and contribute no failures (FR-006)