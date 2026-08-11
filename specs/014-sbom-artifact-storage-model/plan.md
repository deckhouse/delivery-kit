# Implementation Plan: SBOM Artifact Storage Model

## Technical Context

Go 1.24, go-containerregistry v0.20.1 (`remote`, `mutate`, `static`, `partial`), Ginkgo v2 + Gomega, fake registry `pkg/registry` from go-containerregistry for integration tests (with and without Referrers API support). All code lives in `pkg/oci/artifact`; consumers are `pkg/sbom/image`, `pkg/build/sbom_step.go`, `pkg/attestation`, `pkg/storage/repo_stages_storage.go`, `cmd/werf/attest/*`.

### How Storage Works

An artifact (SBOM in a DSSE envelope, attestation) is an OCI image: one layer with the payload, config media type equal to the artifact type, werf annotations in the manifest, and a `subject` pointing at the parent image manifest. The manifest is pushed by digest. The index of all artifacts of a parent digest is an OCI image index published under the canonical referrers tag `sha256-<hex>`.

Two writers maintain that index: werf (`attachDescriptor`, read-merge-push under the tag mutex) and go-containerregistry (`commitSubjectReferrers` inside `remote.Write`, for any manifest with a `subject` on a registry without the Referrers API — mandated of clients by the distribution spec).

### The Problems Solved

1. **Build failures on concurrent attach.** The previous check required the index to be byte-identical to what was pushed. A concurrent write by another image, or a stale read (registries guarantee no read-after-write), failed it; after the retry budget the build failed.
2. **A duplicate entry per artifact.** The go-containerregistry descriptor carries no werf annotations and had a different artifact type, so the `(artifactType, imageName)` eviction never matched it.
3. **Artifacts not self-describing.** Artifact type and annotations existed only in the index descriptor, so a Referrers API response would identify nothing. This also made the manifest digest unusable as artifact identity.
4. **Unsynchronized second writer.** The go-containerregistry index write happened inside `PushArtifactImage`, outside the tag mutex, and could overwrite an entry another goroutine had just published, with no repair possible.

### The Approach

Identity moves into the manifest; the write converges instead of comparing.

1. **Self-describing manifest** (`buildArtifactImage`): artifact type via config media type (no go-containerregistry release can emit the OCI 1.1 manifest-level `artifactType`; the spec falls back to config media type), werf annotations via `mutate.Annotations`. Consequence: the manifest digest becomes a sound artifact identity — distinct artifacts always differ in manifest bytes.
2. **Deduplication by digest**: a descriptor only points at a manifest, so two descriptors sharing a digest describe one artifact regardless of who wrote them. Applied on write (eviction in `updateFallbackIndex`) and on read (`matchDescriptors`, preferring the annotated descriptor — an attach interrupted between push and index update leaves the go-containerregistry descriptor behind).
3. **Convergent attach** (`attachDescriptor`): verify that the index resolves the artifact key to the attached descriptor and to nothing else; if not, merge-and-push again, under exponential backoff (500ms initial, 30s budget). Writers match the key exactly (empty image name included, otherwise an unnamed attach never converges next to named entries); readers keep the empty-name wildcard.
4. **Lock spans the push** (`withTagLock` in `store.go`): serializes the go-containerregistry index write with werf's within a process. `Attach` is unexported so no index update can bypass the lock.

### Alternatives Rejected

| Alternative | Why rejected |
|---|---|
| Per-image tags `sha256-<hex>-<imageName>` (PR #219) | Removes the shared object and thus the race entirely, but leaves the referrers tag schema: SBOMs stop being discoverable by spec-compliant clients (`oras discover`, `cosign` in referrers-tag mode). Canonical tag was required. |
| `remote.WithReferrersTagFallback(false)` (go-containerregistry ≥ v0.21) | Semantics verified empirically: it makes the Referrers API mandatory — the push *fails* on registries without it (leaving an untagged manifest behind), rather than merely skipping the tag write. Also requires go-containerregistry v0.21.8 and Go 1.25. |
| Distributed lock (`pkg/storage/synchronization/lock_manager`) | Serializes werf writers across hosts but cannot make the registry read-after-write consistent, so stale-read lost updates survive; requires a configured synchronization backend; does not cover non-werf writers. Convergence repairs all of these. |
| Removing `subject` from the manifest | Stops go-containerregistry from touching the index, but abandons Referrers API forward compatibility: adding `subject` later changes every manifest digest. |

## Project Structure

| File | Role |
|---|---|
| `pkg/oci/artifact/store.go` | `OCIStore`: `buildArtifactImage`, `Attach` (push + index update under `withTagLock`), content readers |
| `pkg/oci/artifact/fallback.go` | Tag schema, `attachDescriptor` convergence loop, `isAttached`/`isArtifactKey`/`matchDescriptors`, `updateFallbackIndex`, `staticIndex` |
| `pkg/oci/artifact/digest.go` | `DigestHex`, `ResolveTag` |
| `pkg/oci/artifact/attach_integration_test.go` | Attach/read/convergence against a fake registry |
| `pkg/oci/artifact/referrers_compat_test.go` | Discovery via Referrers API on a referrers-capable registry |
| `pkg/oci/artifact/{fallback,store}_internal_test.go`, `fallback_test.go`, `digest_test.go` | Unit specs |

## Complexity Assessment

641 source lines, 1031 test lines, 62 specs. Single package touched; consumers unchanged (public API preserved except `Attach` → unexported, which had one caller in `store.go`). The subtle invariants — exact-vs-wildcard key split and digest-as-identity depending on annotations being in the manifest — are guarded by dedicated specs ("should keep separate entries for different imageNames sharing identical payload", unnamed-artifact suite).
