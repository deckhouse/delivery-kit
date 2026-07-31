# Data Model: VEX Lifecycle in werf.yaml

**Date**: 2026-07-31

## Overview

This document defines the data model, types, and validation rules for VEX support in werf.yaml, following the existing SBOM data model patterns.

## Config Types

### Raw Config (YAML Parsing)

These types mirror the `rawSbom` pattern in `pkg/config/raw_sbom.go`.

```go
// rawVex represents the YAML-level VEX configuration for a single image.
// Example YAML:
//   image: my-app
//   dockerfile: Dockerfile
//   vex: vex/my-app.openvex.json
type rawVex struct {
    // Document is a path to a VEX document file relative to the Git repository root.
    // Required when vex field is present.
    Document string `yaml:"document"`  // tag name "vex" in parent context
}
```

### Normalized Config

These types mirror the `Sbom` type in `pkg/config/sbom.go`.

```go
// Vex represents the validated, normalized VEX configuration for a single image.
type Vex struct {
    // Document is the validated path to a VEX document file.
    Document string
}
```

### Image Config Integration

The `rawStapelImage` and `rawImageFromDockerfile` types gain a new field:

```go
// In raw_stapel_image.go and raw_image_from_dockerfile.go:
RawVex *rawVex `yaml:"vex,omitempty"`
```

The corresponding normalized types get:

```go
// Vex returns the normalized Vex config, or nil if no vex field is set.
Vex() *Vex
```

### No Meta-Level Config

For v1, there is no `meta.build.sbom.vex.enable` toggle. VEX is purely per-image.

## Entity-Relationship

```
┌─────────────────────────┐
│   werf.yaml             │
│                         │
│  meta:                  │
│    build:               │
│      sbom:              │  ← existing, no VEX meta toggle
│        enable: bool     │
│  ┌───────────────────┐  │
│  │ image: my-app     │  │
│  │ dockerfile: ...   │  │
│  │ sbom: {...}       │  │  ← existing
│  │ vex: <path>       │  │  ← NEW (optional)
│  └───────────────────┘  │
│  ┌───────────────────┐  │
│  │ image: other-app  │  │
│  │ dockerfile: ...   │  │
│  │                    │  │  ← no vex field → no VEX operations
│  └───────────────────┘  │
└─────────────────────────┘
           │
           │ vex field resolves to
           ▼
┌──────────────────────────────────────────┐
│  VEX Document (OpenVEX JSON-LD)         │
│                                          │
│  @context: https://openvex.dev/ns/v0.2.0│
│  @id: <document URI>                     │
│  author: <author>                       │
│  timestamp: <ISO 8601>                  │
│  version: <int>                         │
│  statements: [                          │
│    { vulnerability, products, status,   │
│      justification, ... }              │
│  ]                                      │
└──────────────────────────────────────────┘
           │
           │ published as
           ▼
┌──────────────────────────────────────────┐
│  VEX OCI Artifact                         │
│                                          │
│  DSSE Envelope (media type: dsse.v1)    │
│    └── in-toto Statement (type: v1)     │
│        ├── Subject: {image digest}      │
│        └── Predicate: {VEX JSON}        │
│            Type: openvex.dev/ns/v0.2.0   │
│                                          │
│  Stored as: OCI subject attachment       │
│  Subject: image manifest digest          │
│  Fallback tag: sha256-<hex>              │
└──────────────────────────────────────────┘
```

## State Transitions

### VEX Artifact Lifecycle

```
                    ┌──────────────┐
                    │  No VEX      │
                    │  configured  │
                    └──────────────┘
                           │ (vex field added)
                           ▼
                    ┌──────────────┐
             ┌─────│  VEX exists  │◄────┐
             │     │  in Git      │     │
             │     └──────────────┘     │
             │            │              │
             │            │ (build)     │ (image re-
             │            ▼              │  build, no
             │     ┌──────────────┐     │  VEX change)
             │     │  VEX OCI     │─────┘
             │     │  Artifact    │
             │     │  published   │
             │     └──────────────┘
             │            │
             │            │ (VEX file changed)
             │            ▼
             │     ┌──────────────┐
             │     │  Updated     │
             └─────│  VEX OCI     │
                   │  Artifact    │
                   └──────────────┘

Cleanup triggers when image is deleted:
  VEX OCI Artifact → orphaned → removed by SBOM cleanup rules
```

### Change Detection Matrix (FR-011)

| Image Changed | VEX File Changed | Image Manifest | VEX Artifact | Action |
|--------------|------------------|----------------|--------------|--------|
| No | No | Unchanged | Unchanged | No VEX ops |
| Yes | No | Updated | Recreated | Rebuild VEX (bound to image checksum) |
| No | Yes | Unchanged | Updated | New VEX artifact for same image |
| Yes | Yes | Updated | Updated | Both updated |

## Validation Rules (FR-003, FR-010)

| Rule | Condition | Error |
|------|-----------|-------|
| File exists | `vex` field points to non-existent file | `"VEX file not found: <path>"` |
| Git-tracked | `vex` field points to file not tracked by Git | `"VEX file must be tracked by Git: <path>"` |
| Not empty | VEX file is empty | `"VEX file is empty: <path>"` |
| Valid JSON | VEX file is not valid JSON | `"VEX file is not valid JSON: <path>: <parse error>"` |
| Valid OpenVEX | VEX file is valid JSON but not OpenVEX format | `"VEX file is not valid OpenVEX: <path>: <reason>"` |
| Giterminism | File not in Git during giterminism mode | `"VEX file not tracked by Git: <path>"` |

## OCI Artifact Annotations (reused from `pkg/image/const.go`)

| Annotation | Value | Purpose |
|------------|-------|---------|
| `io.werf.image-name` | Image name from werf.yaml | Filtering artifact by image during retrieval |
| `io.werf.checksum` | SHA-256 of VEX file content | Cache invalidation — rebuild only on change |
| `io.werf.target-platform` | Target platform string | Platform-specific VEX artifacts |

## Constants

```go
const (
    // DSSEMediaType is the media type for DSSE envelopes.
    DSSEMediaType = "application/vnd.dsse.envelope.v1+json"

    // InTotoMediaType is the media type for in-toto statements.
    InTotoMediaType = "application/vnd.in-toto+json"

    // VEXPredicateURI is the in-toto predicate type for OpenVEX documents.
    VEXPredicateURI = "https://openvex.dev/ns/v0.2.0"
)
```

## Key Types

```go
// pkg/vex/vex.go

// VEXPredicateURI returns the in-toto predicate URI for VEX documents.
const VEXPredicateURI = "https://openvex.dev/ns/v0.2.0"

// ValidateVEXDocument validates a VEX document file for correct
// OpenVEX JSON-LD format. Returns nil on success or a descriptive error.
func ValidateVEXDocument(data []byte) error
```

```go
// pkg/vex/image/image.go

// PushVEX publishes a VEX document as an OCI artifact attached to
// the specified image manifest via subject reference.
func PushVEX(ctx context.Context, vexJSON []byte, repo, parentDigest, imageName, checksum, targetPlatform string) error

// PullVEX retrieves a VEX document OCI artifact attached to the
// specified image manifest.
func PullVEX(ctx context.Context, repo, parentDigest, imageName string) ([]byte, error)
```