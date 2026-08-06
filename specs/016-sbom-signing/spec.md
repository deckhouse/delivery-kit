# Feature Specification: SBOM Signing at Build Time with Cosign Compatibility

**Feature Branch**: `feat/sbom/sign-sbom-at-build`

**Created**: 2026-08-06

**Status**: migrated

**Input**: Reverse-engineered from branch `feat/sbom/sign-sbom-at-build` (11 commits on top of `origin/main`), the original work plan (`.omo/plans/sbom-signing.md`), the decision ledger (`.omo/drafts/sbom-signing.md`), and the live cosign experiment findings (`.omo/docs/cosign-experiment-findings.md`).

## Project Context

**Delivery Kit** is a Go CLI tool for full-cycle CI/CD to Kubernetes. Relevant subsystems for this feature:

- **SBOM** (`pkg/sbom/`) — SBOM generation (syft/CycloneDX), in-toto/DSSE wrapping, OCI publication
- **Attestation** (`pkg/attestation/`) — DSSE PAE signing/verification, in-toto statements, key loading, Sigstore Bundle serialization
- **Build signing** (`pkg/build/signing/`) — signer construction from `--sign-key`/`--sign-cert`, gating for manifest/ELF/SBOM signing
- **OCI Artifact** (`pkg/oci/artifact/`) — artifact attachment via the referrers fallback-tag index (`sha256-<hex>`)

Before this feature, SBOMs were already wrapped in an in-toto Statement and a DSSE envelope and attached to images as OCI artifacts with a `subject` pointing at the image digest — but the envelope was never signed (a hardcoded nil signer), so consumers could not verify SBOM provenance.

## Customer Decisions (recorded during discovery)

1. No separate signing flow — signing happens inline during `werf build`.
2. The SAME key/cert pair as image manifest signing (`--sign-key`/`--sign-cert`, `WERF_SIGN_KEY`/`WERF_SIGN_CERT`).
3. Verification target is stock **cosign** (new-bundle format), performed offline by clients holding only the bare public key.
4. ГОСТ cryptography is out of scope (cosign does not support it).

## User Scenarios & Testing *(mandatory)*

### User Story 1 — Signed SBOM published during build (Priority: P1)

A release pipeline runs `werf build --sign-key <key> --sign-cert <cert>` (or the env equivalents). The generated SBOM is signed with the provided key and published to the registry as a Sigstore Bundle v0.3 OCI artifact attached to the image.

**Acceptance Scenarios**:

1. **Given** a build with `--sign-key`/`--sign-cert` set, **When** the SBOM converge step runs, **Then** the DSSE envelope is signed (non-empty `signatures`), wrapped in a Sigstore Bundle (`application/vnd.dev.sigstore.bundle.v0.3+json`), and attached to the image's `sha256-<hex>` fallback-tag index with `io.werf.checksum`, `io.werf.image-name`, and `io.werf.target-platform` annotations.
2. **Given** the published artifact, **When** a client runs `cosign verify-attestation --new-bundle-format --trusted-root <empty> --insecure-ignore-tlog=true --key <pub.pem> --type cyclonedx <image>@<digest>` fully offline, **Then** verification passes ("The signatures were verified against the specified public key").
3. **Given** a verifier holding a DIFFERENT public key, **When** the same cosign command runs, **Then** verification fails.
4. **Given** a bundle artifact replaces a previously published bare-DSSE artifact for the same image name, **Then** the stale bare-DSSE entry is removed from the fallback index.

### User Story 2 — Unsigned behavior preserved when no key is set (Priority: P1)

A developer builds locally without any signing flags. SBOM generation and publication behave exactly as before this feature.

**Acceptance Scenarios**:

1. **Given** a build without `--sign-key`, **When** the SBOM is published, **Then** the artifact keeps the legacy bare-DSSE form: artifactType `application/vnd.dsse.envelope.v1+json`, predicateType `https://cyclonedx.org/bom/v1.6`, empty `signatures` array.
2. **Given** a pre-upgrade unsigned bare-DSSE artifact in the registry, **When** `dk sbom get` or `sbom merge` reads it, **Then** the BOM is extracted successfully (dual-format read path).

### User Story 3 — Signing gate and misconfiguration (Priority: P2)

SBOM signing is enabled by the mere presence of `--sign-key` — no extra toggle — while manifest signing stays gated on `--sign-manifest` and ELF signing on its own flags.

**Acceptance Scenarios**:

1. **Given** `--sign-key` and `--sign-cert` without `--sign-manifest`, **Then** the SBOM is signed and the image manifest is NOT signed.
2. **Given** `--sign-key` without `--sign-cert`, **Then** the build fails with "signing certificate is required (the public signing certificate must be specified with --sign-cert option)".
3. **Given** a signer is configured but the produced envelope has zero signatures (internal fault), **Then** the build fails — a silently unsigned artifact is impossible.

### User Story 4 — Cache correctness across signing changes (Priority: P2)

The SBOM artifact cache (keyed by the `io.werf.checksum` annotation) must not serve stale artifacts when the signing configuration or the artifact format changes.

**Acceptance Scenarios**:

1. **Given** an unchanged project rebuilt with the same key, **Then** the cache hits ("Use previously generated SBOM from registry") and nothing is re-published.
2. **Given** signing is newly enabled, or the key is rotated, or the artifact format version is bumped, **Then** the checksum changes, the cache misses, and the SBOM is re-generated and re-published.

### User Story 5 — Multi-platform builds (Priority: P3)

Multi-platform SBOM generation is broken independently of signing (single SBOM per image name, scanned for the host platform only — tracked separately as "C12"). Signing such an SBOM would attest incorrect data.

**Acceptance Scenarios**:

1. **Given** a multi-platform build with `--sign-key`, **Then** the SBOM is generated and attached unsigned exactly as before, and a warning "multi-platform SBOM signing is not yet supported, SBOM will be unsigned" is logged.
2. The guard is a single capability function (`sbomSigningSupported`), so the C12 fix enables signing by changing one predicate.

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: SBOM DSSE envelopes MUST be signed during build whenever `--sign-key` is set, independent of `--sign-manifest`/`--sign-elf-files`.
- **FR-002**: The SBOM signer MUST be the same `signing.Signer` instance used for manifest signing (same key/cert pair); both key and cert remain required.
- **FR-003**: Signed SBOMs MUST be published as Sigstore Bundle v0.3 JSON: `mediaType` `application/vnd.dev.sigstore.bundle.v0.3+json`, `verificationMaterial.publicKey.hint` = base64(SHA-256(DER SPKI of the public key)), `dsseEnvelope` carrying the signed payload.
- **FR-004**: Signed artifacts MUST use predicateType `https://cyclonedx.org/bom` (unversioned, cosign convention); the in-toto statement `_type` stays `https://in-toto.io/Statement/v1` (cosign v2.5.3 accepts it — verified by live experiment).
- **FR-005**: The unsigned path MUST remain byte-form identical to the pre-feature behavior (bare DSSE, versioned predicateType).
- **FR-006**: The read path (pull, cache lookup, `sbom merge`, `attest ls/get/verify`) MUST handle BOTH artifact types, trying the bundle type first and falling back to legacy bare-DSSE; format detection is by fallback-index descriptor `artifactType`, never content sniffing.
- **FR-007**: Publishing a bundle artifact MUST remove the stale bare-DSSE index entry for the same image name (cross-type supersede).
- **FR-008**: The SBOM cache checksum MUST include a bump-able artifact format version and, when signing is enabled, the SHA-256 fingerprint of the signer public key.
- **FR-009**: Signing failures MUST fail the build; a configured signer producing an unsigned envelope MUST be detected and rejected.
- **FR-010**: Multi-platform images MUST keep an unsigned SBOM with a one-line warning until per-platform SBOM generation (C12) is fixed.
- **FR-011**: The Sigstore Bundle serializer MUST be hand-built with no new Go module dependencies (air-gapped constraint).
- **FR-012**: Storage discovery invariants MUST be preserved: fallback tag scheme `sha256-<hex>` and the empty config blob are unchanged (cosign discovery depends on both).

### Key Entities

- **Sigstore Bundle** (`pkg/attestation/bundle.go`) — minimal v0.3 bundle for offline key-based verification; tlog entries, cert chains, and timestamps intentionally omitted.
- **SbomSigningOptions** (`pkg/build/signing/sbom_signing.go`) — Enabled flag + shared `*signing.Signer`, plumbed `BuildOptions → ConveyorOptions → BuildPhase`.
- **ResolveSigningGate** (`pkg/build/signing/resolve.go`) — single source of truth deciding when a signer is required (SBOM/manifest/ELF) and validating key+cert presence.
- **AttachOptions.SupersededTypes** (`pkg/oci/artifact/fallback.go`) — cross-type replacement during fallback-index update.

## Success Criteria *(mandatory)*

- **SC-001**: `werf build --sign-key K --sign-cert C` (single-platform) publishes a signed Sigstore Bundle artifact; verified end-to-end manually with a real registry.
- **SC-002**: Stock cosign v2.5.3 verifies the artifact fully offline with an empty trusted root, `--insecure-ignore-tlog`, and the bare public key; a wrong key fails verification.
- **SC-003**: A build without a key produces artifacts identical in form to `origin/main` behavior.
- **SC-004**: Pre-upgrade bare-DSSE artifacts remain readable by all read paths.
- **SC-005**: Enabling signing, rotating the key, or bumping the format version each invalidate the SBOM artifact cache; an unchanged rebuild hits the cache.
- **SC-006**: `--sign-key` without `--sign-cert` fails with a clear error; a signer that yields zero signatures fails the build.
- **SC-007**: `task format`, `task build`, `task lint`, `task test:unit` pass; the e2e suite (`sbom-signing` label) passes on Linux CI.

## Assumptions

- Signing keys are ECDSA P-256/RSA/Ed25519 in the sigstore-encrypted PEM form ("ENCRYPTED DELIVERY-KIT PRIVATE KEY", empty passphrase via `SkipPassword`) — plain PKCS#8 is rejected by the SDK key loader (see `playground/signing/gen-keys.sh` and `wrap-key`).
- Clients verify with cosign ≥ v2.5.x (new-bundle format support). Legacy cosign `.att` discovery does not find these artifacts.
- The `verificationMaterial` carries only `publicKey.hint`; the signing certificate is NOT embedded in the bundle.

## Documented Decisions (not gaps)

- **Cert fingerprint is NOT part of the cache identity.** The narrow `signature.Signer` interface passed down the SBOM path exposes only the public key, and the published bundle embeds only `publicKey.hint` — a cert-only renewal with the same key would produce a byte-identical artifact, so a cache hit is semantically correct. MUST be revisited if certificates are ever embedded into `verificationMaterial`.
- **Manifest-level `artifactType` is not set on the artifact OCI manifest.** Pre-existing behavior: the vendored go-containerregistry mutate API has no setter for the top-level manifest field. Cosign reads the artifact type from the fallback-index descriptor (which IS set) and verification passes. Cosmetic OCI 1.1 SHOULD-level follow-up for the next change touching `pkg/oci/artifact`.

## Out of Scope

- Per-platform SBOM generation for multi-platform images (C12) — tracked separately, context in `.omo/docs/c12-multiplatform-sbom-context.md`.
- Signing of the merged FSTEC SBOM file produced by `sbom merge` (deferred by the customer).
- ГОСТ signer backend, RFC 3161 timestamps, Rekor/tlog upload, countersigning.
- `werf.yaml` configuration schema (`build.sbom.sign`) and user documentation — deferred until the format stabilizes.
- The duplicate annotation-less fallback-index entry created by go-containerregistry's automatic referrers handling — pre-existing on main, addressed in a separate PR.
