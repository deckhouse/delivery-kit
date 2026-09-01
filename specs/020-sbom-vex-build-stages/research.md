# Research: SBOM and VEX Build Stages

## Decision: Move artifact convergence into the image/stage lifecycle

SBOM and VEX will be represented by non-buildable, mutable build stages that run after the image content stage has produced a registry-backed descriptor. The existing `Stage` lifecycle remains the integration point: stage dependencies determine cache identity, `MutateImage` performs OCI-side publication, and the build phase invokes the stage for each applicable image/platform.

The stages will reuse the existing `sbomStep`, `vexStep`, `pkg/oci/artifact`, signer implementations, and fallback-tag storage. They will not add layers or filesystem content. `BuildPhase.AfterImages` will retain image publication/report work but will no longer be the primary SBOM/VEX generation pass.

### Rationale

- It removes the current repository-dependent post-build pass from `AfterImages`.
- It makes artifact generation part of the same cacheable lifecycle as the descriptor it describes.
- It preserves existing stage cache and secondary-repository restoration behavior.
- It avoids introducing a second artifact storage model or an OCI Referrers migration.

### Alternatives considered

- Keep SBOM/VEX in `AfterImages` and improve propagation: rejected because it preserves the extra post-build pass and allows image publication to become detached from artifact processing.
- Encode SBOM/VEX as image layers: rejected by the specification and would change image semantics.
- Migrate to OCI Referrers: rejected as explicitly out of scope and would break the fallback-tag compatibility baseline.

## Decision: Use explicit artifact subjects for single- and multi-platform images

For a single-platform image, both SBOM and VEX use the published platform manifest descriptor. For a multi-platform image, each SBOM stage uses its platform manifest descriptor, while one VEX stage uses the top-level image index descriptor. Destination propagation resolves the destination descriptor before attaching artifacts.

### Rationale

The repository can contain a destination image with a digest different from the source. Resolving the destination subject prevents an artifact from describing the wrong manifest. It also preserves the established OpenVEX image-level behavior.

### Alternatives considered

- Attach every artifact to the content-stage digest without resolving final/index descriptors: rejected for final repositories and multi-platform images.
- Attach VEX to every platform manifest: rejected because VEX is image-level.

## Decision: Share one propagation contract for all artifact kinds

Introduce one internal propagation operation that accepts source and destination image descriptors and copies all attached SBOM/VEX artifacts idempotently. It is used for primary-to-final, primary-to-cache, and secondary-to-primary copies. Identical repository addresses are skipped. Final-repository errors are fatal; cache errors retain the existing warning/best-effort policy.

### Rationale

The existing `sbomStep.PropagateArtifacts` only names SBOM and is called after image publication. A kind-neutral operation prevents VEX from acquiring different propagation semantics and makes secondary restoration follow the same rules.

### Alternatives considered

- Add a second VEX-specific propagation function: rejected because it duplicates destination resolution, deduplication, and error policy.
- Copy artifacts blindly by source digest: rejected because destination image digests may differ.

## Decision: Keep existing checksum inputs and extend stage dependency identity only where needed

SBOM keeps its current stable checksum inputs: artifact format, scanner/merge/GOST inputs, signer identity, and target platform, with the image stage digest as the parent identity. VEX keeps document content, parent digest, format version, and signer identity. Stage dependency calculation must include the same effective inputs so a changed input cannot reuse an old artifact stage.

### Rationale

Existing checksum logic and tests already encode the required cache behavior. Reusing it minimizes behavioral risk while making stage selection aware of artifact configuration.

### Alternatives considered

- Use only the generated artifact bytes as a cache key: rejected because the stage must decide reuse before expensive generation.
- Add a new cache database: rejected as unnecessary and inconsistent with fallback artifact annotations.

## Decision: Validate registry availability before image building

When SBOM or VEX is enabled, build initialization validates that the configured stage storage is registry-backed. A local-only build fails before image stages execute with an actionable message requiring `--repo` or disabling artifact generation.

### Rationale

Artifacts are OCI registry artifacts and cannot be published to local-only storage. Early validation avoids doing expensive image work that must eventually fail.

### External dependency assessment

No new external dependencies are required. Existing registry, attestation, signing, SBOM, VEX, and storage packages are sufficient.
