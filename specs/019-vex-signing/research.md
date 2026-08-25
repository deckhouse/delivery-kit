# Phase 0 Research: VEX Signing at Build Time

**Feature**: 019-vex-signing | **Date**: 2026-08-21 | **Base**: `main`

All decisions below are grounded in the working tree at branch `feat/sbom/sign-vex` (from `origin/main`) and in industry research of cosign, Tekton Chains, vexctl and docker scout performed during discovery.

## R1: Signing infrastructure reuse

**Decision**: Reuse the 016-sbom-signing infrastructure verbatim: `signing.Signer` (built from `--sign-key`/`--sign-cert` via `signature.ResolveSigningGate` → `cmd/werf/common/signature.go:getSignerOptions`), `attestation.WrapInDSSE`, `attestation.HasSignatures`, `attestation.WrapInBundle`, `attestation.BundleMediaType`. Add `signing.VexSigningOptions` mirroring `signing.SbomSigningOptions` (`pkg/build/signing/sbom_signing.go` — Enabled flag + private `*Signer`), plumbed `BuildOptions → ConveyorOptions → BuildPhase`.

**Rationale**: One key, one signer instance, one bundle serializer — identical trust model and zero new dependencies. `getSbomSigningOptions` (`cmd/werf/common/signature.go:145`) shows the exact gate: `Enabled = SignKey != ""`.

**Alternatives considered**: Reusing `SbomSigningOptions` directly for VEX — rejected: the two artifacts have independent lifecycles and the 016/018 precedent is one options struct per signing target (manifest/SBOM/ELF).

## R2: Artifact kind discrimination — predicate-type annotation in the slot key

**Decision**: Newly published attestations (SBOM and VEX, signed and unsigned) carry the descriptor+manifest annotation `dev.sigstore.bundle.predicateType` = in-toto predicate URI. The fallback-index slot key (`pkg/oci/artifact/fallback.go:isArtifactKey`) becomes `(artifactType, imageName, predicateType-annotation)`; `updateFallbackIndex`/`isAttached` evict only same-key entries, and the cross-type supersede list (`AttachSuperseding`) is likewise scoped by predicate.

**Rationale**: Industry-verified cosign convention: in the new-bundle/OCI-referrers format ALL attestations share one artifactType (`application/vnd.dev.sigstore.bundle.v0.3+json`) and are distinguished by the `dev.sigstore.bundle.predicateType` annotation (sigstore/cosign#3577 discussion and implementation; Tekton Chains writes the same annotation; `cosign verify-attestation` filters on it automatically). This also fixes the latent main defect where SBOM and VEX bare-DSSE artifacts evict each other from the `(artifactType, imageName)` slot.

**Alternatives considered**:
- Separate artifactType per document kind — rejected: contradicts the cosign convention (verified in research), breaks stock cosign discovery, and the sigstore maintainers explicitly rejected parameterized artifactTypes as RFC 6838-invalid.
- Werf-private annotation (`io.werf.predicate-type`) — rejected: cosign's key gives ecosystem interop for free; werf annotations remain for checksum/image-name/platform.
- Fixing discrimination only for VEX — rejected: reads still could not tell a legacy SBOM entry from a legacy VEX entry; the key change must be symmetric to be convergent.

## R3: Legacy entry compatibility on the read path

**Decision**: Reads become predicate-aware with a legacy fallback: `matchDescriptors` gains a predicate filter that (a) matches entries whose annotation equals the requested predicate URI (accepting the openvex alias set, see R5); (b) also yields annotation-less entries as low-priority candidates. Callers (`pullAttestationContent`, `pullSBOMArtifact`, the VEX publish-needed check) verify a legacy candidate by unwrapping it and checking the statement's predicate type before using it — a query for one kind never returns another kind (spec FR-006).

**Rationale**: Registries hold pre-feature artifacts with no annotation forever (migration is out of scope). Content-verification of legacy candidates is cheap (artifacts are KB-sized) and only occurs for entries that predate this feature.

**Alternatives considered**: Treating annotation-less entries as matching any predicate (status quo behavior) — rejected: exactly the misattribution the feature fixes; `attest get --type openvex` on an image with only an SBOM must fail cleanly, not return the SBOM.

## R4: Multi-platform placement and verification target

**Decision**: Unchanged placement from 013: one VEX artifact per image, attached to the image index digest for multi-platform builds (`convergeImageVex` already selects the multiplatform stage descriptor, `pkg/build/build_phase.go:1740`), image manifest digest for single-platform. Signed bundle's in-toto subject = the digest it is attached to. `attest verify`/`attest get` with `--type openvex`: an index reference is used as-is (no `ResolvePlatformDigest` platform expansion, no `ErrIndexPlatformRequired`); passing `--platform` together with `--type openvex` on an index reference is an error explaining VEX is an image-level attestation.

**Rationale**: Industry practice verified: vexctl (`vexctl attest --attach --sign`), docker scout (`docker scout attestation add`) and trivy (`--vex oci`) all attach/discover VEX at the reference digest — image-level, not per-platform. Stock `cosign verify-attestation <index-ref>` also operates on the index digest, so cosign verification works without `--platform`. The 018 "nothing on the index digest" invariant is scoped to SBOM artifacts and is not violated.

**Alternatives considered**: Per-platform VEX copies (N identical documents with different subjects) — rejected by customer during discovery: no new information, N× cost, contradicts ecosystem behavior.

## R5: Predicate type for signed VEX and `--type openvex` resolution

**Decision**: Signed VEX statements use the unversioned predicate `https://openvex.dev/ns`; the unsigned path keeps `https://openvex.dev/ns/v0.2.0` byte-identically. `ResolvePredicateType`/predicate comparison treat `openvex` as an alias set: `{https://openvex.dev/ns, https://openvex.dev/ns/v0.2.0}` — `--type openvex` (and either full URI) matches both on read/verify; writers pick by signing state.

**Rationale**: cosign's well-known `openvex` type is hardcoded to `https://openvex.dev/ns` (`pkg/cosign/attestation/attestation.go:OpenVexNamespace`, verified in source) — stock `cosign verify-attestation --type openvex` matches only that URI, so signed artifacts must use it (mirror of the 016 decision to use unversioned `https://cyclonedx.org/bom` for signed SBOMs). The versioned URI must stay accepted because every pre-feature artifact carries it (and docker scout's convention uses it).

**Alternatives considered**: Keeping `v0.2.0` on the signed path — rejected: stock cosign would require an explicit `--type https://openvex.dev/ns/v0.2.0`, breaking the "works with `--type openvex` out of the box" success criterion.

## R6: Cache checksum composition

**Decision**: Mirror `pkg/build/sbom_step.go:calculateStableChecksum`: the VEX publish checksum becomes a stable hash over {VEX document content, parent digest, `vexArtifactFormatVersion` (new constant, initial value "2"), signer public-key fingerprint (`Signer.Fingerprint()`, empty when unsigned)}. Current composition is `sha256(vexJSON + "-" + parentDigest)` (`pkg/build/vex_step.go:26`), i.e. implicit format version 1.

**Rationale**: Spec FR-007 and the 016 precedent (FR-008): enabling signing, rotating the key, or bumping the format each miss the cache; unchanged unsigned rebuilds of pre-feature artifacts DO miss once (version 1 → 2) — accepted, same as the 016 rollout, and self-heals by republishing an annotated artifact.

**Alternatives considered**: Keeping the unsigned checksum byte-identical (no version component) — rejected: leaves pre-feature unannotated entries in place forever and makes the signed/unsigned checksum composition diverge for no benefit.

## R7: Verification classification for unsigned artifacts

**Decision**: `attest verify --type openvex` against a bare-DSSE (unsigned) artifact fails with the existing `VerifyDSSE` path but the error is classified: "attestation is present but unsigned (legacy format) — rebuild with --sign-key". Reuses `attestation.HasSignatures` (same classification introduced by 018 for SBOM verify-all).

**Rationale**: Spec US5.3; an operator must be able to distinguish "no attestation" / "unsigned" / "wrong key" without reading DSSE internals.

## R8: What is explicitly reused unchanged

- `pkg/attestation/{dsse,bundle,statement,keys}.go` — signing/serialization primitives (016).
- `pkg/oci/artifact/store.go:AttachSuperseding` convergence semantics and tag-lock (016).
- `pkg/vex/vex.go:ValidateVEXDocument` — document validation (013).
- `attest ls` (`pkg/attestation/ls.go`) — already predicate-agnostic (unwraps every DSSE/Bundle entry and prints its predicate); gains nothing but the new entries appearing correctly.
- Giterminism VEX file reading, werf.yaml `vex` schema, cleanup policies (013).
