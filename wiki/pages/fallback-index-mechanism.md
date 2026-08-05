---
title: Fallback Index Mechanism for SBOM Artifacts
type: concept
sources: [S002]
updated: 2026-07-29
---

When multiple container images share the same parent digest, their OCI artifacts (SBOMs, attestations) are stored in a shared OCI Image Index tag called the **fallback index**. Entries within the index are distinguished by the `io.werf.image-name` annotation on each descriptor (S002).

## Operations

- **Push (Attach)**: `Attach()` in `pkg/oci/artifact/fallback.go` reads the current fallback index, calls `updateFallbackIndex()` to add or replace the entry for the given image name, writes the updated index back, and verifies via CAS (compare-and-swap) digest comparison with retries (S002).
- **Lookup (GetAttached)**: `GetAttached()` in `pkg/oci/artifact/fallback.go` pulls the fallback index, filters manifests by `artifactType` and `io.werf.image-name` annotation, and returns the matching descriptor (S002).
- **Entry replacement**: `updateFallbackIndex()` iterates existing manifests and skips (replaces) entries where the `artifactType` and `io.werf.image-name` annotation match the new entry (S002).

## Known problem

The Docker Distribution registry does not reliably preserve the `annotations` field on descriptors within OCI Image Index manifests across write/read cycles. This causes (S002):

- `updateFallbackIndex()` cannot match existing entries (annotation is empty), so entries accumulate instead of being replaced.
- `GetAttached()` cannot find the entry for the requested image name, causing "artifact not found" errors.

See also: [Fallback annotation loss](./fallback-annotation-loss.md), [Attestation subsystem](./attestation-subsystem.md).