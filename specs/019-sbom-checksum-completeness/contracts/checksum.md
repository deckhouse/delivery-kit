# Contract: SBOM Artifact Checksum

**Feature**: specs/019-sbom-checksum-completeness

The checksum is an internal cache-correctness contract, not a public API. Its observable surface is the `WerfChecksumAnnotation` on attached SBOM artifacts and the resulting reuse/regenerate behavior.

## Behavioral contract

Given a parent image stage identified by its registry digest:

1. **Reuse is permitted** only when an attached SBOM artifact carries a checksum equal to the checksum computed from the current build's generation inputs.
2. **Generation inputs** are exactly: artifact format version; scanner settings (image, type, source type, output standard, catalogers with source paths); base/import BOM content; GOST configuration (attack surface, security function); signer identity; target platform.
3. **Exclusions**: image filesystem content (covered by the parent digest), the scratch-base mode, the os-pm packages directive and gomod patcher inputs (covered transitively by the parent digest), externalref enrichment data (non-deterministic), scan source path (per-build stage name).
4. Changing any single generation input MUST change the checksum; identical inputs MUST reproduce the identical checksum.
5. The GOST configuration enters the checksum through exactly one explicit channel (dedicated parts), independent of whether base/import BOMs exist.

## Compatibility

- Checksums produced by previous releases never match the new layout → every image regenerates its SBOM exactly once after upgrade; subsequent builds reuse the cache.
- `MergeOpts.Checksum()` semantics are unchanged (still content-of-BOMs only).
- `sbomArtifactFormatVersion` stays "2"; bumps remain reserved for generator-logic changes.
