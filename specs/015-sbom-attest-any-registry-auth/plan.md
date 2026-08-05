# Implementation Plan: Default Registry Auth for OCI Artifact Attestation Retrieval

**Branch**: `fix/sbom/attest-any-registry-auth` | **Date**: 2026-08-05 | **Spec**: `specs/015-sbom-attest-any-registry-auth/spec.md`

**Input**: Feature specification from `/specs/015-sbom-attest-any-registry-auth/spec.md`

## Summary

Fix `OCIStore.GetAttachedContentAny` to use `s.remoteOptions(ctx)` instead of `s.opts` directly, ensuring consistent authentication behavior across all `OCIStore` methods. Without this fix, callers that rely on default registry auth (from `docker_registry`) would fail when retrieving artifacts using `GetAttachedContentAny`.

## Technical Context

**Language/Version**: Go 1.24.10

**Primary Dependencies**:
- **Container registry**: `google/go-containerregistry`, `werf/common-go`
- **Utilities**: `samber/lo`

**Storage**: OCI container registry (Docker v2, ECR)

**Testing**: Ginkgo for integration tests

**Target Platform**: Linux (amd64/arm64) via Buildah; Kubernetes clusters

### Root Cause

The `OCIStore` struct has two sources of authentication:
1. Explicit `opts []remote.Option` passed via `NewOCIStore(repo, imageName, opts...)`
2. Default auth via `docker_registry.API().RemoteOptionsForHost(ctx, repo)` — used when `opts` is empty

The `remoteOptions(ctx)` helper method encapsulates this fallback logic. Every method on `OCIStore` except `GetAttachedContentAny` uses `remoteOptions(ctx)`. The bug was that `GetAttachedContentAny` used `s.opts...` directly — when no explicit options were provided (the common case for SBOM and attestation callers), it would pass an empty option list, resulting in anonymous/unauthenticated registry access.

### Fix

Changed the `GetAttachedContentAny` call from:
```go
desc, found, err := GetAttached(ctx, s.repo, parentDigest, artifactType, "", s.opts...)
```
to:
```go
desc, found, err := GetAttached(ctx, s.repo, parentDigest, artifactType, "", s.remoteOptions(ctx)...)
```

This is a one-line production change that makes the method consistent with `Attach`, `GetAttached`, `GetAttachedContent`, and `GetContentByDigest`.

## Project Structure

```
pkg/oci/artifact/
  store.go              # OCIStore — fixed GetAttachedContentAny (1 line changed)
  attach_integration_test.go  # Integration test for default registry auth (NEW ~73 lines)
```

## Complexity Assessment

| Factor | Assessment |
|--------|------------|
| Files changed | 2 files (1 production, 1 test) |
| Source lines changed | +1 production line, +73 test lines |
| Dependencies | OCI registry interaction via `go-containerregistry` |
| Risk | Low — one-line production change, consistent with existing pattern |
| Test coverage | Integration test covers the fixed path with a real basic-auth registry |

## Impacted Callers

- `pkg/attestation/get.go:44` — `pullAttestationContent()` calls `GetAttachedContentAny` when `imageName` is empty
- `pkg/sbom/image/image.go:77` — `PullSBOM()` calls `GetAttachedContentAny` when `imageName` is empty

Both callers now use the correct default registry authentication instead of anonymous access.