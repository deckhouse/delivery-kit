---
title: Fallback Index Mechanism for SBOM Artifacts
type: concept
sources: [S002, S016, S019, S020]
updated: 2026-08-10
---

When multiple container images share the same parent digest, their OCI artifacts (SBOMs, attestations) are stored in a shared OCI Image Index tag called the **fallback index**. Entries within the index are distinguished by the `io.werf.image-name` annotation on each descriptor (S002).

For multi-platform images, per-platform SBOMs each use a **distinct** fallback tag, one per platform manifest digest, rather than sharing the index-level fallback tag. This avoids entry collisions between platforms and keeps the in-toto subject truthful (S020).

## Operations

- **Push (Attach)**: `Attach()` in `pkg/oci/artifact/fallback.go` serialises writers per `(repo, parentDigest)` via an in-process tag lock, then performs a **convergent write**: the descriptor being attached is **merged** into the index state that was just pulled, never replacing the index with locally constructed state alone (S019). After writing, it enters a convergence loop (exponential backoff, 30 s budget) that observes the index until the entry is present and deduplicated. Previously, the implementation used a per-tag mutex with CAS-based consistency verification (S016), and before that, CAS-only retry (3 tries, ~3.5s) without per-tag serialisation (S002).
- **Lookup (GetAttached)**: `GetAttached()` in `pkg/oci/artifact/fallback.go` pulls the fallback index, filters manifests by `artifactType` and `io.werf.image-name` annotation, and returns the matching descriptor (S002).
- **Entry management**: Entries are collapsed by **manifest digest**: if two descriptors reference the same manifest digest, the werf-annotated one is kept and the go-containerregistry-generated one (without werf annotations) is dropped — both on write (eviction) and on read (deduplication). The `matchDescriptors` function identifies the correct entry by `(artifactType, imageName)`, with an empty image name treated as matching any image for reading (S019).

## Known problem (mitigated)

Docker Distribution does not reliably preserve the `annotations` field on OCI Image Index descriptors across write/read cycles. This is mitigated by the convergent write model: entries are matched by manifest digest rather than by annotation alone. If a descriptor's annotations are lost, the descriptor for the same manifest (written by go-containerregistry) still carries the same digest, and the deduplication logic collapses them (S019).

See also: [Fallback annotation loss](./fallback-annotation-loss.md), [Attestation subsystem](./attestation-subsystem.md).