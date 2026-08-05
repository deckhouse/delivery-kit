---
title: Fallback Index Annotation Loss
type: decision
sources: [S002]
updated: 2026-07-29
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

## Non-functional requirement

The eventual fix must not depend on annotations on OCI Image Index descriptors for distinguishing image entries (NF2 in spec). This means the fallback index mechanism will need a different keying strategy — likely moving the image-name into the tag or content rather than relying on the descriptor annotation (S002).

See also: [Fallback index mechanism](./fallback-index-mechanism.md).