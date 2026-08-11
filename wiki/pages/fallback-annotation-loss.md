---
title: Fallback Index Annotation Loss
type: decision
sources: [S002, S016, S019, S020]
updated: 2026-08-10
---

## Problem

The Docker Distribution registry does not reliably preserve the `annotations` field on descriptors within OCI Image Index manifests. The fallback index mechanism relies on `io.werf.image-name` annotations to distinguish entries for different images sharing the same parent digest — when the registry drops the annotations, entries become indistinguishable (S002).

## Chosen approach (regression test)

No production code fix was implemented. Instead, a Ginkgo regression test was added at `test/e2e/sbom/regressions_test.go` that (S002):

1. Builds two images sharing the same parent digest.
2. Pulls the fallback index directly via `go-containerregistry`.
3. Asserts that `io.werf.image-name` annotations are present for both entries.

## Fixture isolation

The regression test uses a dedicated fixture at `test/e2e/sbom/_fixtures/regressions/manifest_annotation/` that is structurally independent from the `lifecycle/multi_image` fixture. This prevents CI interference — concurrent test execution would otherwise cause fallback index tag collisions and false-positive failures. The fixture has a unique project name, its own `Dockerfile.builder-base`, its own `werf-giterminism.yaml`, and no shared directories with `lifecycle/multi_image` (S002).

## Production fix (per-tag mutex + consistency verification, superseded)

[description as is, then add:]

This approach was itself superseded by a **convergent write model** (S019). The per-tag mutex is still used within a single process, but the write strategy changed: instead of writing a locally-constructed index and verifying digest equality, the descriptor is **merged** into whatever the registry currently holds, so concurrent writers (including go-containerregistry's own writes) do not lose each other's entries. Entries are collapsed by manifest digest, not by annotation matching (S019).

See also: [Fallback index mechanism](./fallback-index-mechanism.md), [Per-platform SBOM](./per-platform-sbom.md).

## Per-platform SBOM model (annotation loss avoided)

Multi-platform images now use per-platform SBOMs, each stored on a **distinct fallback tag** of its own platform manifest digest (S020). Because each platform's SBOM occupies its own tag rather than sharing an index-level fallback tag, the annotation-loss problem does not arise — there is no shared index where entries must be distinguished by annotation. The annotation-loss concern is limited to the shared fallback index used by single-platform images sharing a parent digest.