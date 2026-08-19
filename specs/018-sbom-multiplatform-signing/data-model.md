# Data Model: Signing of Multi-Platform SBOMs

**Feature**: 018-sbom-multiplatform-signing

No new stored formats. All registry artifacts, tags, annotations, and checksums are inherited unchanged from 016-sbom-signing and 016-sbom-multiplatform-per-platform. The feature adds one in-memory result type and removes one predicate.

## Unchanged (inherited invariants)

| Entity | Source | Invariant preserved |
|---|---|---|
| Signed SBOM artifact | 016-sbom-signing | Sigstore Bundle v0.3, `application/vnd.dev.sigstore.bundle.v0.3+json`, unversioned predicateType `https://cyclonedx.org/bom`, `publicKey.hint` |
| Unsigned SBOM artifact | pre-016 | bare DSSE `application/vnd.dsse.envelope.v1+json`, versioned predicateType, empty `signatures` |
| Per-platform attachment | 016-multiplatform | in-toto `subject` = platform manifest digest; artifact on that digest's `sha256-<hex>` fallback tag; nothing on the index digest |
| Cache checksum | both | components: scan/merge inputs + `signerIdentity` + `targetPlatform` (each independent; empty values omitted) — composition untouched |
| Fallback-index replace key | 016-signing | `(artifactType, io.werf.image-name)` incl. cross-type supersede (bundle replaces bare-DSSE) |

## Removed

- **`sbomSigningSupported(images []*image.Image) bool`** (`pkg/build/build_phase.go:408`) — the single-platform capability guard from 016-sbom-signing FR-010, together with its warning branch in `convergeImageSbom`. After removal, `SbomSigningOptions.Enabled` alone decides whether the signer is passed to every platform's converge.

## New (in-memory only)

### Per-platform verification result (`pkg/attestation`)

Produced by the index-aware verification entry point for each platform manifest of an index; drives the verify-all table and the aggregate verdict.

| Field | Type | Meaning |
|---|---|---|
| Platform | string | normalized `os/arch[/variant]` from the index entry (`unknown/unknown` entries never appear — filtered by `ListIndexPlatforms`) |
| Digest | string | platform manifest digest (`sha256:...`) |
| Status | enum | see states below |
| Err | error | underlying cause for non-verified states (nil for `verified`) |

**Status states** (constitution: no `iota`, type-name-prefixed string constants):

| State | Condition (per R3) | Operator meaning |
|---|---|---|
| verified | DSSE signature verifies against a provided key; predicate type matches | platform attested |
| missing | artifact pull fails with `artifact.ErrNotFound` | no attestation — was it ever built with SBOM? |
| unsigned | envelope present, `HasSignatures` = false (legacy bare-DSSE) | rebuild with `--sign-key` |
| invalid | signatures present, `VerifyDSSE` fails (or predicate-type mismatch / unwrap error) | wrong key or tampered artifact |

**Aggregate rule**: overall verification succeeds iff every result is `verified`; the failure error names each non-verified platform with its state.

### State transitions

None persisted. Registry-side artifact lifecycle (unsigned → superseded by signed on rebuild with key) is the existing 016 cross-type supersede behavior, now merely reachable per platform.
