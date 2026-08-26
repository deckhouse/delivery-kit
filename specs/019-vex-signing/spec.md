# Feature Specification: VEX Signing at Build Time with Cosign Compatibility

**Feature Branch**: `feat/sbom/sign-vex`

**Created**: 2026-08-21

**Status**: Draft

**Input**: User description: "Реализовать функционал подписания VEX аналогично подписанию SBOM (016-sbom-signing) и multiplatform SBOM (018-sbom-multiplatform-signing). Предварительный анализ механизма подписания в delivery-kit и ресёрч индустрии (cosign, vexctl, docker scout) выполнены; решения по развилкам зафиксированы заказчиком."

## Project Context

**Delivery Kit** is a Go CLI tool for full-cycle CI/CD to Kubernetes. It is built on top of werf with Deckhouse Platform extensions. Subsystems touched by this feature:

- **VEX** (`pkg/vex/`, `pkg/vex/image/`) — OpenVEX document validation and OCI publication
- **Build** (`pkg/build/`) — VEX convergence during image build (`vex_step`, `convergeImageVex`)
- **Build signing** (`pkg/build/signing/`) — signer construction from `--sign-key`/`--sign-cert`
- **Attestation** (`pkg/attestation/`) — DSSE signing/verification, Sigstore Bundle serialization, `attest` command internals
- **OCI artifacts** (`pkg/oci/artifact/`) — cosign-compatible artifact storage via the referrers fallback-tag index (`sha256-<hex>`)
- **CLI** (`cmd/werf/attest/`) — attestation commands (`verify`, `get`, `ls`)

### Prior state (all on `main`)

- **013-vex-lifecycle**: a `vex` field in werf.yaml points to an OpenVEX (JSON-LD) file under Git; at build time the document is wrapped in an in-toto Statement and a DSSE envelope and attached to the image as an OCI artifact — but the envelope is never signed (a hardcoded nil signer). For multi-platform images the single VEX artifact is attached to the image **index digest** (VEX is an image-level document, not a per-platform one). The publish cache is keyed by a checksum of the VEX content and the parent digest.
- **016-sbom-signing**: the signing infrastructure exists and is proven for SBOMs — one `--sign-key`/`--sign-cert` pair produces signed Sigstore Bundle v0.3 artifacts verifiable by stock cosign offline, with an unsigned path preserved byte-identically, a dual-format read path, and cache invalidation on key changes.
- **Latent defect**: an artifact slot in the fallback-tag index is keyed by (artifact type, image name) only. SBOM and VEX artifacts share the same artifact types (bare-DSSE unsigned; Sigstore Bundle signed), so on a single-platform image with both features enabled the two artifacts **evict each other** from the index. Existing e2e suites never combine SBOM and VEX on one image, so the defect is unobserved.

## Customer Decisions (recorded during discovery)

1. **Signing gate**: VEX signing is enabled by the mere presence of `--sign-key` (same rule as SBOM signing, no separate toggle). The same key/cert pair and the same signer instance as manifest and SBOM signing are used.
2. **Artifact discrimination follows cosign convention**: attestations of different kinds keep the SAME artifact type and are distinguished by the predicate-type annotation `dev.sigstore.bundle.predicateType` on the artifact descriptor (industry research: cosign new-bundle format, Tekton Chains). The fallback-index slot key gains a predicate dimension so SBOM and VEX artifacts coexist and each supersedes only its own kind — fixing the latent collision on both the signed and unsigned paths.
3. **Multi-platform placement unchanged**: the VEX artifact (signed or not) stays attached to the image index digest with the in-toto subject = index digest — matching industry practice (vexctl, docker scout, trivy attach VEX to the reference digest, image-level). No per-platform VEX artifacts.
4. **Cache correctness**: the VEX publish checksum incorporates the signer public-key fingerprint and a bump-able artifact format version (mirror of SBOM signing), so enabling signing or rotating the key republishes the artifact.
5. **Verification**: `attest verify --type openvex` on a reference that resolves to an image index verifies the attestation attached to the **index digest** itself (no per-platform expansion — VEX artifacts do not exist per platform).
6. **Signed predicate type is unversioned**: signed VEX attestations use predicate type `https://openvex.dev/ns` (cosign's `openvex` well-known type), so stock `cosign verify-attestation --type openvex` works out of the box; the unsigned path keeps the versioned `https://openvex.dev/ns/v0.2.0` byte-identically to today (mirror of the CycloneDX unversioned-predicate decision in 016).
7. Work is based on `main` (not on the unmerged 018 branch).

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Signed VEX published during build (Priority: P1)

A release pipeline runs `werf build --sign-key <key> --sign-cert <cert>` (or env equivalents) for a project where an image declares a `vex` document. The VEX document is signed with the provided key and published as a Sigstore Bundle v0.3 OCI artifact attached to the image — to the image manifest digest for single-platform builds, to the image index digest for multi-platform builds.

**Why this priority**: This is the feature itself — supply-chain consumers can trust VEX statements only if their provenance is verifiable.

**Independent Test**: Build an image with a `vex` field and a signing key against a test registry, then inspect the fallback tag of the image digest.

**Acceptance Scenarios**:

1. **Given** a single-platform build with `--sign-key`/`--sign-cert` and a `vex` field, **When** the VEX converge step runs, **Then** the image manifest digest has exactly one attached Sigstore Bundle artifact (`application/vnd.dev.sigstore.bundle.v0.3+json`) whose DSSE envelope is signed (non-empty `signatures`), whose in-toto `subject` digest equals the image manifest digest, whose predicate type is `https://openvex.dev/ns`, and whose descriptor carries the `dev.sigstore.bundle.predicateType` annotation with that value.
2. **Given** a two-platform build with the same flags, **When** the build completes, **Then** exactly one signed VEX bundle is attached to the image **index** digest (in-toto subject = index digest) and no VEX artifact is attached to any platform manifest digest.
3. **Given** the published artifact, **When** a client runs stock cosign `verify-attestation --new-bundle-format --key <pub.pem> --insecure-ignore-tlog=true --type openvex <image ref>` fully offline, **Then** verification passes; a different public key fails.
4. **Given** a configured signer produces an envelope with zero signatures (internal fault), **Then** the build fails with an error naming the image — a silently unsigned VEX artifact is impossible.
5. **Given** a signed bundle replaces a previously published unsigned bare-DSSE VEX artifact for the same image, **Then** the stale bare-DSSE entry is removed from the fallback index (cross-type supersede), while SBOM entries of the same image are untouched.

---

### User Story 2 - SBOM and VEX artifacts coexist on one image (Priority: P1)

A project enables both SBOM generation and a VEX document for the same image. After a build (with or without a signing key), both artifacts are present in the registry, independently discoverable, and each is replaced only by its own kind on subsequent builds.

**Why this priority**: Today the two artifacts evict each other from the index slot — signing VEX without fixing discrimination would silently destroy signed SBOMs, corrupting the supply chain rather than strengthening it.

**Independent Test**: Build an image with both `build.sbom.enable` and a `vex` field, then list attached artifacts for the image digest and assert both kinds are present.

**Acceptance Scenarios**:

1. **Given** a single-platform build with SBOM enabled and a `vex` field, without a signing key, **When** the build completes, **Then** the image digest carries BOTH a bare-DSSE SBOM artifact and a bare-DSSE VEX artifact, and `attest ls` lists both with their predicate types.
2. **Given** the same project built WITH a signing key, **Then** the image digest carries both a signed SBOM bundle and a signed VEX bundle, each verifiable independently via `attest verify --type cyclonedx` and `--type openvex`.
3. **Given** both artifacts exist, **When** only the VEX file changes and the image is rebuilt, **Then** only the VEX artifact is republished; the SBOM artifact and its index entry are byte-identical to before.
4. **Given** artifacts published before this feature (no predicate-type annotation on their descriptors), **When** any read path runs (`sbom get`, `sbom merge`, `attest ls/get/verify`, VEX cache check), **Then** they remain readable (legacy annotation-less entries are still matched).

---

### User Story 3 - Unsigned behavior preserved when no key is set (Priority: P2)

A developer builds locally without signing flags. VEX publication behaves exactly as before this feature.

**Why this priority**: Regression protection — the unsigned path is the default for every developer today.

**Independent Test**: Rebuild the existing VEX lifecycle e2e fixtures without a key and compare artifact form with pre-feature output.

**Acceptance Scenarios**:

1. **Given** a build without `--sign-key`, **When** the VEX artifact is published, **Then** it keeps the legacy form: artifact type `application/vnd.dsse.envelope.v1+json`, predicate type `https://openvex.dev/ns/v0.2.0`, empty `signatures` array.
2. **Given** a pre-upgrade unsigned VEX artifact in the registry, **When** `attest get --type openvex` or `attest verify` reads it, **Then** the document is extracted successfully (dual-format read path: bundle first, bare-DSSE fallback).

---

### User Story 4 - Cache correctness across signing changes (Priority: P2)

The VEX publish cache must not serve a stale unsigned artifact once a key is introduced, and must keep serving the cached artifact on unchanged rebuilds.

**Why this priority**: A cache that ignores the signing configuration would make enabling signing a silent no-op for existing images.

**Independent Test**: Build with a key, rebuild unchanged, then rotate the key and rebuild again, observing publish decisions in the build log.

**Acceptance Scenarios**:

1. **Given** an unchanged project rebuilt with the same key, **Then** the VEX artifact is not republished (cache hit is logged).
2. **Given** a project previously built WITHOUT a key, **When** it is rebuilt WITH a key, **Then** the checksum changes, the cache misses, and a signed bundle is published, superseding the stale bare-DSSE entry.
3. **Given** the key is rotated, **Then** the cache misses and the VEX artifact is re-signed and republished.
4. **Given** the image content changes but the VEX file does not, **Then** the VEX artifact is recreated for the new digest (existing image-binding rule from 013 is preserved).
5. **Given** the key is removed on a rebuild, **Then** the cache misses, an unsigned bare-DSSE artifact is published, and the stale signed bundle entry is evicted.

---

### User Story 5 - Verification of a signed VEX attestation (Priority: P2)

An operator gates a pipeline on `werf attest verify --repo <repo> --key <pub.pem> --type openvex <ref>`. For a single-platform reference the image manifest attestation is verified; for an index reference the attestation attached to the index digest is verified.

**Why this priority**: Verification is the consumer half of the feature; without it the signature is write-only.

**Independent Test**: Sign and publish a VEX for a multi-platform image, then run `attest verify --type openvex` with the index reference and the correct/wrong public keys.

**Acceptance Scenarios**:

1. **Given** a signed VEX on a single-platform image, **When** `attest verify --type openvex` runs with the correct key, **Then** it succeeds; with a wrong key it fails.
2. **Given** a signed VEX on a multi-platform image, **When** `attest verify --type openvex` runs with the index reference and no `--platform`, **Then** the index-digest attestation is verified (no per-platform expansion and no `--platform`-required error).
3. **Given** an unsigned legacy VEX artifact, **When** `attest verify --type openvex` runs, **Then** it fails with a clear "unsigned" classification rather than a generic parse error.

---

### Edge Cases

- **Both SBOM and VEX signed on a multi-platform image**: SBOM bundles live on platform manifest digests, the VEX bundle on the index digest — no shared slot, but `attest ls` on the index reference must present both layers coherently.
- **Legacy annotation-less entries mixed with new annotated entries** for the same image (partial republish after this feature ships): reads must prefer an exact predicate match and fall back to legacy entries without misattributing an SBOM entry to a VEX query or vice versa.
- **Interrupted first signed build**: bare-DSSE VEX still in the index alongside nothing else; the next build converges (supersede is part of the convergence predicate, self-healing).
- **`--sign-key` without `--sign-cert`**: the build fails with the existing clear error before any VEX work starts (shared signing gate).
- **VEX file removed from werf.yaml after a signed artifact was published**: no VEX operations occur; the stale artifact remains until registry cleanup (unchanged 013 lifecycle).
- **Registry without OCI subject-reference support**: the existing descriptive error from 013 applies unchanged.

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: VEX DSSE envelopes MUST be signed during build whenever `--sign-key` is set, independent of `--sign-manifest`/`--sign-elf-files`, using the same signer instance (key/cert pair) as manifest and SBOM signing.
- **FR-002**: Signed VEX artifacts MUST be published as Sigstore Bundle v0.3 JSON (`application/vnd.dev.sigstore.bundle.v0.3+json`, `verificationMaterial.publicKey.hint`), with in-toto predicate type `https://openvex.dev/ns` and the in-toto subject equal to the digest the artifact is attached to.
- **FR-003**: The multi-platform placement MUST be preserved: exactly one VEX artifact per image, attached to the image index digest for multi-platform builds and to the image manifest digest for single-platform builds; nothing VEX-related is attached to platform manifest digests.
- **FR-004**: The unsigned path MUST remain byte-form identical to pre-feature behavior: bare DSSE, versioned predicate type `https://openvex.dev/ns/v0.2.0`, empty signatures; descriptors of newly published artifacts additionally carry the predicate-type annotation per FR-005 (payload byte-form is unchanged).
- **FR-005**: Artifact descriptors of newly published attestations MUST carry the predicate-type annotation `dev.sigstore.bundle.predicateType`, and the fallback-index slot key MUST include the predicate dimension so that: (a) SBOM and VEX artifacts on the same digest coexist; (b) an attach supersedes only entries of its own predicate kind (including the cross-type bare-DSSE → bundle supersede); (c) entries without the annotation are treated as legacy and remain readable and supersedable by their own kind.
- **FR-006**: All read paths (`attest ls/get/verify`, VEX publish-needed cache check, SBOM read paths) MUST select artifacts predicate-aware: an exact predicate-annotation match is preferred, legacy annotation-less entries are matched only when they unwrap to the requested predicate kind, and a query for one kind MUST never return an artifact of another kind.
- **FR-007**: The VEX publish checksum MUST incorporate a bump-able artifact format version and, when signing is enabled, the signer public-key fingerprint — so enabling signing, rotating the key, or bumping the format each republish the artifact, while unchanged rebuilds keep hitting the cache.
- **FR-008**: Signing failures MUST fail the build; a configured signer producing an envelope with zero signatures MUST be detected and rejected before publish.
- **FR-009**: Cross-type supersede scoped to the VEX predicate kind MUST work in both directions: publishing a signed bundle removes the stale bare-DSSE VEX entry, and publishing an unsigned artifact (after the key is removed) removes the stale bundle entry — a read never prefers a stale artifact of the previous signing state.
- **FR-010**: `werf attest verify --type openvex` (and `attest get`) given a reference that resolves to an image index MUST operate on the attestation attached to the index digest without requiring `--platform`; behavior for non-index references is unchanged.
- **FR-011**: The read path MUST handle both artifact formats for VEX (bundle first, legacy bare-DSSE fallback) and accept both the versioned and unversioned OpenVEX predicate types when unwrapping.
- **FR-012**: Storage discovery invariants MUST be preserved: fallback tag scheme `sha256-<hex>`, empty config blob, and artifact-type declaration via config media type are unchanged (stock cosign discovery depends on them).

### Key Entities

- **Signed VEX artifact** — Sigstore Bundle v0.3 wrapping a signed DSSE envelope with an in-toto statement whose predicate is the OpenVEX document; one per image, attached to the image (index) digest.
- **Predicate-type annotation (`dev.sigstore.bundle.predicateType`)** — the cosign-convention descriptor annotation that discriminates attestation kinds sharing one artifact type; becomes part of the fallback-index slot identity.
- **VexSigningOptions** — Enabled flag + shared signer, plumbed through build options alongside the existing SBOM signing options.
- **VEX publish checksum** — cache identity of the VEX artifact: document content + parent digest + artifact format version + signer public-key fingerprint (when signing).

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: `werf build --sign-key K --sign-cert C` for an image with a `vex` field publishes exactly one signed Sigstore Bundle VEX artifact at the image (index) digest — proven by e2e against a real registry for both single- and multi-platform builds.
- **SC-002**: Stock cosign (≥ v2.5.x) verifies the published VEX attestation fully offline with `--type openvex`, the bare public key and ignore-tlog; a wrong key fails — proven manually end-to-end once, with in-process DSSE verification covering the same assertion in e2e.
- **SC-003**: An image with both SBOM and VEX enabled carries both artifacts after a build, each independently retrievable and verifiable, and rebuilding with only one input changed republishes only that artifact — proven by e2e.
- **SC-004**: A build without a key produces VEX artifacts identical in form to pre-feature output, and pre-upgrade artifacts remain readable by all read paths — proven by existing VEX lifecycle e2e passing plus a legacy-artifact read test.
- **SC-005**: Enabling signing or rotating the key republishes the VEX artifact; an unchanged rebuild does not — proven by e2e log assertions.
- **SC-006**: `task format`, `task build`, `task lint`, `task test:unit` pass; the VEX and SBOM-signing e2e suites pass on Linux CI.

## Assumptions

- Signing key material constraints are inherited from 016-sbom-signing: sigstore-encrypted PEM ("ENCRYPTED DELIVERY-KIT PRIVATE KEY"), Ed25519 primary / ECDSA P-256 / RSA; clients verify with cosign ≥ v2.5.x (new-bundle format).
- The OpenVEX document itself is validated as today (013); this feature does not change document validation.
- Industry alignment is with the cosign referrers/new-bundle convention (same artifact type + predicate-type annotation), as established by research of cosign, Tekton Chains, vexctl and docker scout; docker scout's buildx-style attestation manifests are a different mechanism and are out of scope.
- The 018 multiplatform-SBOM-signing branch is independent: its "nothing on the index digest" invariant applies to SBOM artifacts only, and this feature does not conflict with it merging in either order.

## Out of Scope

- `werf.yaml` configuration schema for signing (e.g. `vex.sign`) and user documentation — deferred until the format stabilizes (same as 016).
- Signing of merged/aggregated VEX documents or any per-platform VEX artifacts.
- ГОСТ signer backend, RFC 3161 timestamps, Rekor/tlog upload, countersigning.
- Changes to registry cleanup policies for VEX (013 rules unchanged).
- `attest sign` (post-hoc signing of already-published VEX artifacts).
- Republishing or migrating pre-existing artifacts to add the predicate-type annotation.
