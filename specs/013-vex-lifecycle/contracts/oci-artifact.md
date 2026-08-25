# OCI Artifact Contract: VEX Document Attachment

**Date**: 2026-07-31
**Contract Type**: Storage / Protocol

## Overview

This contract defines how VEX documents are stored and retrieved as OCI artifacts in the container registry. It mirrors the SBOM OCI artifact contract exactly, using the same DSSE/in-toto envelope pattern.

## Artifact Format

```json
{
  "dsse_envelope": {
    "payload": "<base64-encoded-in-toto-statement>",
    "payloadType": "application/vnd.in-toto+json",
    "signatures": []
  }
}
```

Where the in-toto statement payload decodes to:

```json
{
  "type": "https://in-toto.io/Statement/v1",
  "subject": [
    {
      "name": "<image-repo>",
      "digest": { "sha256": "<image-manifest-digest-hex>" }
    }
  ],
  "predicateType": "https://openvex.dev/ns/v0.2.0",
  "predicate": { <OpenVEX-JSON-LD-document> }
}
```

## Media Types

| Component | Media Type |
|-----------|------------|
| **OCI artifact** (DSSE envelope layer) | `application/vnd.dsse.envelope.v1+json` |
| **in-toto statement** (payload) | `application/vnd.in-toto+json` |
| **VEX predicate** (in-toto predicate) | `https://openvex.dev/ns/v0.2.0` |

## Storage Model

VEX documents are stored as OCI subject reference artifacts attached to the image manifest.

### Primary Storage (OCI Subject References)

When the registry supports OCI subject references (OCI Distribution Spec v1.1+):

```
Image Manifest (digest: sha256:<image-digest>)
  └── Subject Reference ──► VEX Artifact Manifest
                              ├── artifactType: application/vnd.dsse.envelope.v1+json
                              ├── annotations:
                              │   ├── io.werf.image-name: "<image-name>"
                              │   ├── io.werf.checksum: "<vex-content-sha256>"
                              │   └── io.werf.target-platform: "<platform>"
                              └── Layer (DS content-type)
                                  └── DSSE envelope (JSON)
```

### Fallback Storage (OCI Tag)

When the registry does not support subject references:

```
Image Manifest (digest: sha256:<image-digest>)
Ancillary tag: sha256-<image-digest-hex>

Artifact Index (tagged: sha256-<image-digest-hex>)
  └── Entries (deduplicated by artifactType + imageName)
      ├── { digest: <vex-manifest-digest>, ... }
      └── { digest: <sbom-manifest-digest>, ... }
```

## Retrieval API

### `PushVEX(ctx, vexJSON, repo, parentDigest, imageName, checksum, targetPlatform) error`

Publishes a VEX document as an OCI artifact.

**Parameters**:
- `vexJSON` — Raw VEX document JSON (OpenVEX format)
- `repo` — OCI repository (e.g., `registry.example.com/my-project`)
- `parentDigest` — Digest of the image manifest to attach to (e.g., `sha256:abc123...`)
- `imageName` — Image name from werf.yaml (used for annotation and fallback)
- `checksum` — SHA-256 hex digest of the VEX content (used for cache invalidation)
- `targetPlatform` — Target platform (e.g., `linux/amd64`)

**Flow**:
1. Compute `digestHex` from `parentDigest`
2. Wrap VEX JSON in in-toto statement: `WrapInInTotoStatement(vexJSON, VEXPredicateURI, repo, digestHex)`
3. Wrap statement in DSSE envelope: `WrapInDSSE(stmtBytes, InTotoMediaType)`
4. Create `OCIStore(repo, imageName)`
5. Call `store.Attach(parentDigest, DSSEMediaType, envelopeBytes, checksum, targetPlatform)`

### `PullVEX(ctx, repo, parentDigest, imageName) ([]byte, error)`

Retrieves a VEX document from its attached OCI artifact.

**Parameters**:
- `repo` — OCI repository
- `parentDigest` — Digest of the parent image
- `imageName` — Image name (optional — empty for "any")

**Flow**:
1. Create `OCIStore(repo, imageName)`
2. Call `store.GetAttachedContent(parentDigest, DSSEMediaType)` (with imageName) or `GetAttachedContentAny(parentDigest, DSSEMediaType)` (without)
3. Unwrap DSSE: `UnwrapDSSE(envelopeJSON, InTotoMediaType)`
4. Unwrap in-toto statement: `UnwrapInTotoStatement(stmtBytes)`
5. Verify predicate type is `VEXPredicateURI`
6. Return predicate (VEX document JSON)

## Cleanup

### Lifecycle

- VEX artifacts are cleaned up by the same SBOM cleanup rules (FR-007).
- When an image is deleted from the registry, its VEX artifact becomes unreferenced.
- Orphaned VEX artifacts are removed during the next cleanup run.

### Identification

VEX artifacts are distinguished from SBOM artifacts by their in-toto predicate type:
- VEX: `https://openvex.dev/ns/v0.2.0`
- SBOM: `https://cyclonedx.org/bom/v1.6`

When cleaning fallback indices, the cleanup code filters entries by `WerfImageNameAnnotation` to match artifacts to existing images. No separate VEX cleanup logic is needed.

## Related

- Data model: [data-model.md](../data-model.md)
- Config contract: [config.md](config.md)