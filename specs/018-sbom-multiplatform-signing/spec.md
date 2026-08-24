# Feature Specification: Signing of Multi-Platform SBOMs

**Feature Branch**: `feat/sbom/sign-multiplatform-sbom`

**Created**: 2026-08-19

**Status**: Draft

**Input**: User description: "Enable SBOM signing for multi-platform images: per-platform SBOMs are now honest (016-sbom-multiplatform-per-platform), so the capability guard blocking signing (FR-010 / User Story 5 of 016-sbom-signing) must be lifted, and verification of an index reference must cover all platforms by default."

## Project Context

**Delivery Kit** is a Go CLI tool for full-cycle CI/CD to Kubernetes. It is built on top of werf with Deckhouse Platform extensions. Subsystems touched by this feature:

- **Build** (`pkg/build/`) — SBOM convergence during image build; the multi-platform signing capability guard (`sbomSigningSupported`)
- **Build signing** (`pkg/build/signing/`) — signer construction from `--sign-key`/`--sign-cert`
- **Attestation** (`pkg/attestation/`) — DSSE signing/verification, Sigstore Bundle serialization
- **OCI artifacts** (`pkg/oci/artifact/`) — cosign-compatible artifact storage, index platform resolution
- **CLI** (`cmd/werf/attest/`) — attestation commands (`verify`, `get`, `ls`)

### Prior state (both features already on `main`)

- **016-sbom-signing**: single-platform SBOMs are signed at build time when `--sign-key`/`--sign-cert` is set and published as Sigstore Bundle v0.3 artifacts verifiable by stock cosign offline. Multi-platform builds were deliberately left unsigned behind a single capability predicate with the warning "multi-platform SBOM signing is not yet supported, SBOM will be unsigned", because the multi-platform SBOM lied about its platform (C12).
- **016-sbom-multiplatform-per-platform**: C12 is fixed — each platform manifest gets its own honest SBOM (scanned for that platform, in-toto `subject` = platform manifest digest, attached to that digest's fallback tag, nothing attached to the index digest).

The signing spec anticipated this moment: the guard is a single capability function so that "the C12 fix enables signing by changing one predicate".

## Customer Decisions (recorded during discovery)

1. **No index-level artifacts.** Only per-platform SBOMs are signed; nothing is ever attached to the index digest. No merged or aggregate index-level SBOM or signature.
2. **`attest verify` on an index reference verifies ALL platforms by default.** `--platform` becomes an optional narrowing filter for `verify`. `attest get` and `sbom get` keep the strict mandatory `--platform` behavior (they return a single document, so "all platforms" is meaningless there).
3. **A signing failure for any platform fails the whole build** (consistent with FR-009 of 016-sbom-signing: a silently unsigned artifact is impossible).
4. **Cache invalidation on enabling signing is accepted**: the first signed build of an existing multi-platform project regenerates the SBOMs of all platforms (same precedent as single-platform).
5. Work is based on `main`; previous out-of-scope items remain out of scope (see below).

## Clarifications

### Session 2026-08-19

- Q: When signing one platform's SBOM fails during a multi-platform build, fail fast or converge the remaining platforms first and fail with an aggregated error? → A: Fail-fast — the first signing failure immediately fails the build; remaining platform SBOMs are not converged (the key is shared, so a signing failure is systemic; the 017 continue-and-aggregate semantics apply to PURL enrichment errors only).
- Q: How should verify-all classify a platform whose artifact exists but is an unsigned legacy bare-DSSE? → A: A distinct third failure category, "present but unsigned (legacy format)", telling the operator to rebuild with a signing key — separate from "missing attestation" and "invalid signature".
- Recorded without a question (determined by existing machinery): index entries with `unknown/unknown` platform (e.g. buildx attestation manifests) are skipped by index platform resolution and therefore excluded from verify-all — werf never attaches SBOMs to such entries.

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Multi-platform build publishes a signed SBOM per platform (Priority: P1)

A release pipeline runs `werf build --sign-key <key> --sign-cert <cert>` (or env equivalents) for a project with `platform: [linux/amd64, linux/arm64]` and `build.sbom.enable`. Each platform manifest gets its own SBOM signed with the provided key, published as a Sigstore Bundle v0.3 artifact attached to that platform manifest's fallback tag — exactly the same artifact form as the single-platform signed case.

**Why this priority**: This is the feature itself — one key, N honest signed attestations, unblocking supply-chain requirements for multi-arch releases.

**Independent Test**: Build a two-platform image with a signing key against a test registry, then inspect the fallback tags of both platform manifest digests.

**Acceptance Scenarios**:

1. **Given** a two-platform build with `--sign-key`/`--sign-cert`, **When** the SBOM converge step runs, **Then** each platform manifest digest has exactly one attached Sigstore Bundle artifact (`application/vnd.dev.sigstore.bundle.v0.3+json`) whose DSSE envelope is signed (non-empty `signatures`) and whose in-toto `subject` digest equals that platform manifest digest.
2. **Given** the same build, **When** it completes, **Then** the warning "multi-platform SBOM signing is not yet supported" does NOT appear anywhere in the output, and no artifact is attached to the index digest.
3. **Given** the published artifacts, **When** a client runs stock cosign `verify-attestation --new-bundle-format --key <pub.pem> --insecure-ignore-tlog=true --platform <platform> <index-ref>` fully offline for each platform, **Then** verification passes for both platforms; a different public key fails for both.
4. **Given** signing of one platform's SBOM fails (internal fault: configured signer yields zero signatures), **Then** the build fails with an error naming the image and platform.

---

### User Story 2 - `attest verify` on an index reference verifies all platforms by default (Priority: P1)

An operator gates a deployment on `werf attest verify --repo <repo> --key <pub.pem> <index-ref>`. Without `--platform`, the command resolves the index, verifies the SBOM attestation of EVERY platform, and succeeds only if all platforms carry a valid signed attestation. With `--platform`, only that platform is verified.

**Why this priority**: Verification is a gate; a gate that silently checks one platform out of two is a trap. "Signed with one key — verified with one command" is the expected UX.

**Independent Test**: Run `attest verify` on a signed two-platform image without `--platform`; then delete one platform's attestation and observe the aggregate failure.

**Acceptance Scenarios**:

1. **Given** a two-platform image with both SBOMs signed, **When** `attest verify` runs with the index reference and no `--platform`, **Then** it verifies both platform attestations and reports success per platform.
2. **Given** one platform's attestation is missing, unsigned (bare-DSSE), or signed with a different key, **When** the same command runs, **Then** it fails with an error naming the failing platform(s), even if the other platform verifies.
3. **Given** `--platform linux/arm64` is passed with the index reference, **Then** only the arm64 attestation is verified.
4. **Given** a single-platform (non-index) reference, **When** `attest verify` runs without `--platform`, **Then** behavior is unchanged from today (single manifest verified).
5. **Given** an index reference, **When** `attest get --tag <tag>` or `sbom get --tag <tag>` runs without `--platform`, **Then** it still fails listing available `platform → digest` pairs (unchanged strict behavior).

---

### User Story 3 - Existing behavior preserved: single-platform and unsigned builds (Priority: P2)

A developer builds a single-platform project (with or without a key) or a multi-platform project without a key. Nothing changes.

**Why this priority**: Regression protection for the two features being joined.

**Independent Test**: Rebuild existing single-platform signed and multi-platform unsigned fixtures and compare artifacts with pre-feature output.

**Acceptance Scenarios**:

1. **Given** a single-platform build with `--sign-key`, **Then** the published artifact is byte-form identical to the pre-feature signed output (same bundle format, same checksum, cache hits on rebuild).
2. **Given** a multi-platform build WITHOUT `--sign-key`, **Then** each platform keeps the legacy unsigned bare-DSSE artifact exactly as on `main` today, with no warning about signing.
3. **Given** pre-upgrade artifacts (signed single-platform bundles, unsigned per-platform bare-DSSE), **When** any read path runs (`sbom get`, `sbom merge`, `attest ls/get/verify`), **Then** they remain readable via the existing dual-format read path.

---

### User Story 4 - Cache correctness when signing is enabled for multi-platform (Priority: P2)

The SBOM artifact cache must serve signed per-platform artifacts on unchanged rebuilds and must not serve stale unsigned artifacts once a key is introduced.

**Acceptance Scenarios**:

1. **Given** an unchanged two-platform project rebuilt with the same key, **Then** both platform SBOMs are served from the registry cache ("Use previously generated SBOM from registry") and nothing is re-published.
2. **Given** a project previously built multi-platform WITHOUT a key, **When** it is rebuilt WITH a key, **Then** the checksum changes for every platform, the cache misses, and signed bundles are generated and published for all platforms (superseding the stale bare-DSSE entries per the existing cross-type supersede rule).
3. **Given** the key is rotated, **Then** all platform caches miss and re-sign.

---

### Edge Cases

- **Mixed formats across platforms** (one platform has a signed bundle, another still has bare-DSSE — e.g. after an interrupted first signed build): `attest verify` without `--platform` fails classifying the platform as "present but unsigned (legacy format)"; a rebuild converges the remaining platform (per-platform converge is independent and self-healing).
- **Index with a platform that has no SBOM attestation at all** (e.g. artifacts deleted manually): verify-all fails naming that platform with the "missing attestation" classification.
- **Index entries without a real platform** (`unknown/unknown`, e.g. buildx attestation manifests): excluded from verify-all by index platform resolution; they never carry werf SBOMs.
- **`--platform` value not present in the index**: existing `ResolvePlatformDigest` error listing available platforms applies unchanged.
- **Verification key mismatch on all platforms**: aggregate error lists every platform as failed, not just the first.

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: Multi-platform SBOMs MUST be signed during build whenever `--sign-key` is set: the capability guard restricting SBOM signing to single-platform image sets MUST be removed, along with the "multi-platform SBOM signing is not yet supported" warning. All platforms of an image MUST be signed by the same signer instance (same key/cert pair as single-platform and manifest signing).
- **FR-002**: Each signed per-platform artifact MUST have the identical form to the single-platform signed artifact (Sigstore Bundle v0.3, unversioned predicateType, `publicKey.hint` verification material), with in-toto `subject` = platform manifest digest and attachment to that digest's fallback tag.
- **FR-003**: No artifact of any kind may be attached to the index digest (unchanged invariant from 016-sbom-multiplatform-per-platform FR-009).
- **FR-004**: A signing failure for any platform MUST fail the build fail-fast with an error naming the image and platform — remaining platform SBOMs are not converged; a configured signer producing an envelope with zero signatures MUST be detected and rejected (extends 016-sbom-signing FR-009 to every platform).
- **FR-005**: `werf attest verify` given a reference that resolves to an image index and no `--platform` MUST verify the attestations of ALL platforms in the index (index entries with `unknown/unknown` platform are excluded, per existing index platform resolution) and succeed only if every platform verification succeeds; the failure report MUST name each failing platform and classify each failure as one of: missing attestation, present but unsigned (legacy bare-DSSE), or invalid signature.
- **FR-006**: `werf attest verify` with `--platform` MUST verify only the named platform (existing behavior); non-index references MUST behave exactly as today.
- **FR-007**: `werf attest get`, `werf sbom get` MUST keep the strict behavior: an index reference without `--platform` fails listing available `platform → digest` pairs. `werf attest ls`, `werf attest sign`, `werf sbom merge`, `werf sbom validate` MUST remain unchanged.
- **FR-008**: The SBOM cache checksum composition MUST NOT change: the target platform and the signer public-key fingerprint remain independent components, so single-platform checksums (signed and unsigned) and unsigned multi-platform checksums stay byte-identical to `main`.
- **FR-009**: The unsigned multi-platform path (no `--sign-key`) MUST remain byte-form identical to current `main` behavior (per-platform bare-DSSE, versioned predicateType, no warning).
- **FR-010**: All read paths MUST keep handling both artifact formats per platform (bundle first, legacy bare-DSSE fallback), including within the verify-all index expansion.

### Key Entities

- **Per-platform signed SBOM artifact** — Sigstore Bundle v0.3 attached to a platform manifest digest's fallback tag; N of them per multi-platform image, all signed by the same key; the only signed SBOM entity (no index-level counterpart).
- **Capability guard (`sbomSigningSupported`)** — the single predicate introduced by 016-sbom-signing to block multi-platform signing; this feature removes it.
- **Index verification expansion (`attest verify`)** — resolution of an index reference into its platform manifest digests (existing `ListIndexPlatforms`/`ResolvePlatformDigest` machinery, already used by `attest ls`) followed by per-platform verification and aggregate verdict.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: A two-platform build with a signing key publishes exactly one signed Sigstore Bundle per platform manifest digest, with correct per-platform subjects and truthful platform annotations, and nothing on the index digest — proven by e2e against a real registry.
- **SC-002**: Stock cosign (≥ v2.5.x) verifies each platform's attestation fully offline (`--platform <p> <index-ref>`, bare public key, ignore-tlog); a wrong key fails — proven manually end-to-end once (cosign is optional in CI), with in-process DSSE verification covering the same assertion in e2e.
- **SC-003**: `attest verify` on the index reference without `--platform` passes when all platforms are signed and fails naming the platform when any platform's attestation is removed, unsigned, or signed by a different key — proven by e2e.
- **SC-004**: Single-platform builds (signed and unsigned) and unsigned multi-platform builds produce artifacts identical in form to `main`, and their caches hit on unchanged rebuilds — proven by existing e2e suites passing unmodified plus golden checksum tests.
- **SC-005**: An unchanged two-platform signed rebuild hits the cache for both platforms; enabling signing or rotating the key misses the cache for all platforms.
- **SC-006**: `task format`, `task build`, `task lint`, `task test:unit` pass; the e2e suites under the `sbom-signing` and `multiplatform` labels (both labeled `simple`, running in the `e2e_simple` CI job) pass on Linux CI.

## Assumptions

- Signing key material constraints are inherited from 016-sbom-signing: sigstore-encrypted PEM ("ENCRYPTED DELIVERY-KIT PRIVATE KEY"), Ed25519 primary / ECDSA P-256 / RSA; clients verify with cosign ≥ v2.5.x.
- CI e2e runners support pulling foreign-arch images (QEMU/binfmt already exercised by the `multiplatform` label suite); the cosign binary is NOT installed in CI, so e2e relies on in-process DSSE verification with cosign steps executed only when the binary is available.
- The per-platform converge loop and its failure semantics (including the aggregated PURL error handling from 017-sbom-converge-failure-semantics) are taken as-is from `main`; signing errors are not PURL-enrichment errors and fail the build immediately per FR-004.
- `attest verify` currently fails on index references without `--platform` via `ErrIndexPlatformRequired`; no user depends on that error as a contract (the command is young), so changing it to verify-all is not a breaking change requiring a flag.

## Out of Scope

- Index-level artifacts of any kind: merged index-level SBOM, index-digest signature, aggregate attestation (customer decision 1).
- Signing of the merged FSTEC SBOM file produced by `sbom merge` (still deferred by the customer).
- ГОСТ signer backend, RFC 3161 timestamps, Rekor/tlog upload, countersigning.
- `werf.yaml` configuration schema (`build.sbom.sign`) and user documentation — still deferred until the format stabilizes.
- Changes to `attest sign` (post-hoc signing of already-published SBOMs), `attest get`, `sbom get` platform UX (strict `--platform` stays).
- Verify-all expansion for `sbom get`/`attest get` (single-document commands).
