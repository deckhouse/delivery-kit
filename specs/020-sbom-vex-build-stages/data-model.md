# Data Model: SBOM and VEX Build Stages

## Artifact stage

An internal build-stage operation associated with the final image digest (and, for SBOM, a target platform). `SbomStage` and `VexStage` are the sole owners of their respective generation, cache, signing, and publication behavior; no `sbomStep` or `vexStep` compatibility layer remains. These stages are OCI-artifact stages, not image-content stages.

| Field | Description |
|---|---|
| Stage name | Stable stage identifier for cache/logging and stage selection. |
| Final image descriptor | The final image manifest or image index whose digest is the artifact subject. |
| Target platform | Required for platform-specific SBOM; empty for image-level multi-platform VEX. |
| Artifact kind | CycloneDX SBOM or OpenVEX. |
| Generation inputs | Scanner/merge inputs for SBOM, document content for VEX, format version, and signer identity. |
| Mutable/buildable flags | Non-buildable and mutable, matching registry-only stages such as signing, but unlike signing the output is an associated OCI artifact rather than a manifest mutation. |
| Storage abstraction | `storage.StagesStorage` used for all registry operations. |

Validation rules:

- The final image descriptor/digest must be available before `MutateImage` runs.
- The stage must use `storage.StagesStorage` for registry access.
- SBOM for a multi-platform image must use the corresponding platform manifest.
- VEX must use the platform manifest for single-platform images and the top-level index for multi-platform images.
- An enabled artifact stage requires registry-backed storage.

## Artifact identity

The cache identity stored with the existing fallback artifact index and calculated directly by the owning artifact stage. It identifies the associated final image digest, not a synthetic artifact image.

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

The artifact stage does not become an image layer and does not operate on an image filesystem. It publishes separate OCI artifacts whose subjects are the final image descriptors. All registry interaction is performed through `storage.StagesStorage`; existing fallback-tag indexes remain the source of truth and remain readable by current consumers.
