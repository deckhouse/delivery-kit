# Data Model: SBOM and VEX Build Stages

## Artifact stage

An internal build-stage operation associated with an image (and, for SBOM, a target platform).

| Field | Description |
|---|---|
| Stage name | Stable stage identifier for cache/logging and stage selection. |
| Parent descriptor | The image manifest or image index that the artifact describes. |
| Target platform | Required for platform-specific SBOM; empty for image-level multi-platform VEX. |
| Artifact kind | CycloneDX SBOM or OpenVEX. |
| Generation inputs | Scanner/merge inputs for SBOM, document content for VEX, format version, and signer identity. |
| Mutable/buildable flags | Non-buildable and mutable, matching registry-only stages such as signing. |

Validation rules:

- A parent descriptor must be available before `MutateImage` runs.
- SBOM for a multi-platform image must use the corresponding platform manifest.
- VEX must use the platform manifest for single-platform images and the top-level index for multi-platform images.
- An enabled artifact stage requires registry-backed storage.

## Artifact identity

The cache identity stored with the existing fallback artifact index.

| Field | Description |
|---|---|
| Kind and format | Artifact predicate/media type and format version. |
| Parent digest | Digest of the descriptor described by the artifact. |
| Effective inputs | Scanner, merge, GOST, VEX document content, and platform inputs as applicable. |
| Signer identity | Signing fingerprint, or empty for unsigned artifacts. |
| Artifact checksum | Stable checksum used to detect reusable attached artifacts. |

An identity is reusable only when all effective inputs and the parent descriptor identity match. Repeated publication with the same identity is idempotent.

## Artifact destination

A repository and the image descriptor published there.

| Field | Description |
|---|---|
| Repository address | Primary, final, cache, or secondary repository. |
| Image digest | Destination digest, resolved after image copy. |
| Artifact set | All attached SBOM/VEX artifacts applicable to that descriptor. |
| Failure policy | Fatal for final publication; best effort for cache mirrors. |

Propagation skips equal source/destination addresses and does not duplicate an already-present artifact identity.

## Relationships and transitions

```text
content stage -> artifact stage -> image publication
secondary stage + artifacts -> primary stage + artifacts
primary image + artifacts -> final image + artifacts
primary image + artifacts -> cache image + artifacts
```

The artifact stage does not become an image layer. It publishes separate OCI artifacts whose subjects are resolved image descriptors. Existing fallback-tag indexes remain the source of truth and remain readable by current consumers.
