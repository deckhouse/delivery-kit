# Data Model: SBOM Checksum Completeness

**Feature**: specs/019-sbom-checksum-completeness | **Date**: 2026-08-24

No persistent data structures change. The feature redefines the derivation of one value.

## SBOM artifact checksum

- **Where produced**: `sbomStep.calculateStableChecksum` (`pkg/build/sbom_step.go`).
- **Where stored**: `image.WerfChecksumAnnotation` annotation on the SBOM artifact attached to the image stage in the registry.
- **Where compared**: `sbomStep.ConvergeWithMerge` — equality against the annotation of an already-attached artifact for the same parent digest; match → reuse, mismatch/absent → regenerate.

### Inputs (after this feature)

| # | Part (keyed) | Source | Covers |
|---|---|---|---|
| 1 | format version (`"2"`) | `sbomArtifactFormatVersion` const | Generator/converter logic changes |
| 2 | `scan` | `scanner.ScanOptions.Checksum()` | Scanner image+version, scanner type, source type, output standard, catalogers + source paths |
| 3 | `merge` | `cyclonedxutil.MergeOpts.Checksum()` | Content of base BOM and import BOMs (`StableBOMChecksum`) |
| 4 | `gost_attack_surface` | `mergeOpts.Gost.AttackSurface` | GOST post-processing config (NEW) |
| 5 | `gost_security_function` | `mergeOpts.Gost.SecurityFunction` | GOST post-processing config (NEW) |
| 6 | `signer` | `signerIdentity` | Signing key fingerprint (empty when unsigned) |
| 7 | `platform` | `targetPlatform` | Target platform (empty for single-platform) |

All parts are always present (fixed arity); empty string denotes "unset". Parts are passed as separate arguments to `util.Sha256Hash(parts...)` (`":::"`-joined internally), never pre-joined.

### Intentional exclusions (documented at computation site)

| Excluded input | Why safe |
|---|---|
| Image filesystem content (packages, lock files, pm metadata) | Covered by parent stage digest — the other half of the cache key |
| Scratch-base mode (`from: scratch`) | Changing the base image changes every stage digest → parent digest |
| os-pm `packages` directive | Package list feeds the Packages stage digest via the generated install command; the stage appears/disappears with the directive → parent digest |
| gomod patcher inputs (go.mod/go.sum@commit, imageContext) | Changes alter build context → stage digest; logic changes → format version bump |
| externalref enrichment data | External, non-deterministic input; cannot be pinned |
| `ScanCommand.SourcePath` | Stage name; varies per build without affecting SBOM content |

### Invariants

- **Completeness**: any input change that alters regeneration output for the same parent digest changes the checksum.
- **Stability**: identical inputs always produce an identical checksum.
- **Injectivity over parts**: distinct part sequences produce distinct hash inputs (fixed arity + keyed parts + separator not producible by any part value).
- **Single channel for GOST**: the config enters the checksum only via parts 4–5; the `prepareGostComponents` side effects on base/import BOMs remain but are no longer the only channel.
