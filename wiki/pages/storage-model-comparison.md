---
title: Storage Model Comparison for Multi-Platform SBOM
type: decision
sources: [S021]
updated: 2026-08-11
---

## The problem

All three models solve the same problem: given an OCI Image Index referencing N platform manifests, how should per-platform SBOM artifacts be stored, linked, and discovered? (S021)

## Models compared

### delivery-kit / werf: tag-based adjacency (fallback tags)

Each platform manifest has its own fallback tag (`sha256-<platform-digest>`). That fallback tag points to an OCI Artifact Index whose descriptors point to the SBOM and provenance artifacts for that platform. The platform manifests themselves remain pure — no artifact entries in the top-level Image Index (S021).

**Trade-off**: registry-agnostic (any OCI registry works) and cosign-compatible (cosign uses the same per-digest fallback tag walk). The cost is O(N) tag enumeration for discovery (S021).

### BuildKit: single-index model with embedded attestation manifests

All artifacts (SBOM, provenance) are first-class entries in the same OCI Image Index as the platform manifests — no separate fallback tags needed. Discovery is a simple index enumeration walk. Attestation manifests use `platform: "unknown/unknown"` so runtimes don't try to execute them (S021).

**Trade-off**: trivial enumeration, zero extra tag operations. The cost is that every artifact grows the image index, and naive clients that enumerate the index to find runnable images may be confused by non-image entries (S021).

### OCI Spec: referrers API model

Each SBOM is a standalone OCI Image Manifest with `artifactType` declaring what it is and `subject` declaring which platform manifest it references. Discovery uses the Referrers API (`GET /v2/<name>/referrers/<digest>`), which returns descriptors of all manifests whose `subject` points to the queried digest — no fallback tags and no index modification needed (S021).

**Trade-off**: clean separation of concerns (index describes runnable images, referrers API describes attestations). The cost is registry support for the Referrers API endpoint (OCI distribution-spec 1.1), which is not yet universally available. The referrers tag schema exists as a fallback (S021).

## Where they agree

All three models generate one SBOM per platform manifest, not one merged SBOM at the index level. All use some form of `subject` reference pointing at the target platform manifest digest. None modifies the target manifest — linking is always weak (artifact → target) and never alters the attested manifest (S021).

## Where they differ

| Dimension | delivery-kit | BuildKit | OCI Spec |
|-----------|-------------|----------|----------|
| Discovery | Fallback tag enumeration | Index walk | Referrers API |
| Index growth | Stable (N entries) | Grows with artifacts | Stable (N entries) |
| Registry requirement | None | None (annotation fallback) | Referrers API |
| Artifact visibility | Hidden inside fallback tags | Visible in index | Via API query |
| Format coupling | DSSE envelope (cosign compat) | OCI manifest + in-toto layer | Open |

## Relevance to delivery-kit

The delivery-kit model is a hybrid: OCI fallback tag schema (same schema as the distribution-spec 1.1 referrers tag schema fallback) for discovery, DSSE envelopes for cosign compatibility, explicit prohibition of index-level artifacts (matching OCI Spec's per-manifest idiom), and no artifact embedding in the Image Index (unlike BuildKit) (S021).

See also: [Per-platform SBOM](./per-platform-sbom.md)
