# Contract: fallback-index artifact slot discrimination

**Feature**: 019-vex-signing

Internal storage contract of `pkg/oci/artifact` consumed by SBOM, VEX and attest read/write paths.

## Slot key

```
(artifactType, io.werf.image-name annotation, dev.sigstore.bundle.predicateType annotation)
```

- Annotation absent ⇒ predicate component `""` (legacy).
- Writers occupy exactly one slot; the attach converges until the key resolves to the pushed descriptor and nothing else.

## Write rules

| Writer | artifactType | predicate annotation | Superseded keys |
|---|---|---|---|
| unsigned SBOM | DSSE | `https://cyclonedx.org/bom/v1.6` | own legacy (`DSSE`, `""` **content-verified as SBOM**) |
| signed SBOM | Bundle | `https://cyclonedx.org/bom` | (`DSSE`, cyclonedx aliases), own legacy |
| unsigned VEX | DSSE | `https://openvex.dev/ns/v0.2.0` | own legacy (`DSSE`, `""` **content-verified as VEX**), (`Bundle`, openvex aliases) on key removal |
| signed VEX | Bundle | `https://openvex.dev/ns` | (`DSSE`, openvex aliases), own legacy |

A writer never evicts an entry of a different predicate kind. Legacy (`""`) entries are evicted only after content verification establishes their kind.

## Read rules

1. Filter index entries by artifactType and (when set) image name — as today.
2. Prefer entries whose predicate annotation ∈ requested alias set.
3. Annotation-less entries are legacy candidates: use only after unwrapping proves statement predicateType ∈ requested alias set.
4. Never return an artifact whose proven kind differs from the requested kind.

## Compatibility

- Pre-feature artifacts (annotation-less) stay readable, verifiable and supersedable by their own kind forever; no migration/rewrite of existing registry content.
- Discovery invariants untouched: fallback tag `sha256-<hex>`, empty config blob, artifactType declared via config.mediaType, werf annotations duplicated on descriptor and manifest.
- go-containerregistry's automatic annotation-less duplicate descriptor (known 016 artifact) continues to be deduplicated by digest in reads and evicted by digest in writes.
