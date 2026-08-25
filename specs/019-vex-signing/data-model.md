# Data Model: VEX Signing at Build Time

**Feature**: 019-vex-signing | **Date**: 2026-08-21

## Stored artifacts (OCI registry)

### Signed VEX artifact (NEW)

| Property | Value |
|---|---|
| Artifact type / config mediaType | `application/vnd.dev.sigstore.bundle.v0.3+json` |
| Payload | Sigstore Bundle v0.3 JSON: `verificationMaterial.publicKey.hint` = base64(SHA-256(DER SPKI)), `dsseEnvelope` with non-empty `signatures` |
| in-toto statement | `_type` `https://in-toto.io/Statement/v1`, predicateType `https://openvex.dev/ns`, subject = attached digest |
| Predicate | The OpenVEX document verbatim |
| Attached to | Image manifest digest (single-platform) / image index digest (multi-platform), via fallback tag `sha256-<hex>` |
| Descriptor+manifest annotations | `io.werf.checksum`, `io.werf.image-name`, `io.werf.target-platform` (when set), **`dev.sigstore.bundle.predicateType`=`https://openvex.dev/ns`** (NEW) |
| Cardinality | Exactly one per image name per digest |

### Unsigned VEX artifact (form unchanged, annotation added)

| Property | Value |
|---|---|
| Artifact type | `application/vnd.dsse.envelope.v1+json` |
| Payload | Bare DSSE envelope, empty `signatures`, predicateType `https://openvex.dev/ns/v0.2.0` |
| Annotations | As today plus **`dev.sigstore.bundle.predicateType`=`https://openvex.dev/ns/v0.2.0`** on newly published artifacts |

### SBOM artifacts (annotation added on new publishes)

Byte form of payloads unchanged (016/018 contracts). Newly published SBOM artifacts additionally carry `dev.sigstore.bundle.predicateType` = `https://cyclonedx.org/bom` (signed) / `https://cyclonedx.org/bom/v1.6` (unsigned). Existing registry entries are never rewritten.

## Fallback-index slot identity (CHANGED)

```
Before: slot key = (artifactType, io.werf.image-name)
After:  slot key = (artifactType, io.werf.image-name, dev.sigstore.bundle.predicateType)
```

- **Writers** (`isArtifactKey`, `updateFallbackIndex`, `isAttached`): exact-match all three components; an entry missing the predicate annotation has predicate `""` — legacy entries of the writer's own kind are superseded via the explicit superseded-key list, never by accidental key collision.
- **Cross-type supersede** (`AttachSuperseding` superseded list): scoped to the same predicate kind — a signed VEX bundle supersedes the bare-DSSE VEX entry (annotated with the openvex alias or legacy annotation-less **iff** content-verified as VEX by the publish path) and never touches SBOM entries.
- **Readers** (`matchDescriptors` + callers): exact predicate-annotation matches first; annotation-less entries are legacy candidates that MUST be content-verified (unwrap → statement predicateType ∈ requested alias set) before use.

## Predicate alias sets

| Kind | Canonical (signed) | Accepted on read |
|---|---|---|
| VEX (`openvex`) | `https://openvex.dev/ns` | `https://openvex.dev/ns`, `https://openvex.dev/ns/v0.2.0` |
| SBOM (`cyclonedx`) | `https://cyclonedx.org/bom` | `https://cyclonedx.org/bom`, `https://cyclonedx.org/bom/v1.6` (existing dual-predicate read path, unchanged) |

## VexSigningOptions (NEW, `pkg/build/signing/`)

Mirror of `SbomSigningOptions`: `Enabled bool` (set when `--sign-key` non-empty) + private `*Signer` (shared instance). Plumbed `cmd/werf/common` → `BuildOptions` → `ConveyorOptions` → `BuildPhase` → `convergeImageVex` → `vexStep.Converge` → `vexImage.PushVEX`.

## VEX publish checksum (CHANGED)

```
Before: sha256(vexJSON + "-" + parentDigest)                          // implicit format v1
After:  stable-hash{vexJSON, parentDigest, vexArtifactFormatVersion="2", signerFingerprint|""}
```

State transitions driven by the checksum (`io.werf.checksum` annotation comparison):

| Registry state | Build config | Action |
|---|---|---|
| v2 artifact, checksum equal | same inputs | skip publish (cache hit) |
| v1 legacy artifact (any) | any | checksum differs → republish (annotated v2 artifact) |
| unsigned v2 | key added | fingerprint enters checksum → republish signed bundle, supersede bare-DSSE |
| signed v2 | key rotated | fingerprint changes → republish |
| signed v2 | key removed | fingerprint leaves checksum → republish unsigned bare-DSSE, supersede bundle |

## Verification classification (`attest verify --type openvex`)

| Artifact state | Result |
|---|---|
| Signed bundle, key matches | success, predicate printed |
| Signed bundle, no key matches | signature verification error |
| Bare-DSSE (unsigned, legacy or keyless build) | error: present but unsigned (legacy format), advise rebuild with `--sign-key` |
| Nothing attached | not-found error (existing) |
| Index reference | verified at the index digest itself; `--platform` combined with `--type openvex` on an index → usage error |

## Invariants preserved

- Fallback tag scheme `sha256-<hex>`, empty config blob, artifactType via config.mediaType (cosign discovery, 016 FR-012).
- One VEX document per image; nothing VEX-related on platform manifest digests (013).
- SBOM artifacts and their platform placement are untouched by the VEX write path.
- `attest ls` output shape (predicate type derived from content) — new annotation is additive.
