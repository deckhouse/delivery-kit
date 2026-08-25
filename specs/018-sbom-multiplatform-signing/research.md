# Research: Signing of Multi-Platform SBOMs

**Feature**: 018-sbom-multiplatform-signing | **Date**: 2026-08-19

All findings verified against `origin/main` (`e2a9f3546`).

## R1. Capability guard removal site and fail-fast semantics

**Decision**: Remove `sbomSigningSupported` (`pkg/build/build_phase.go:408`) and the warning branch in `convergeImageSbom` (`build_phase.go:316-323`); pass the signer unconditionally when `phase.SbomSigningOptions.Enabled`. Fail-fast comes for free: `convergeImageSbom` iterates platforms sequentially and returns on the first `convergePlatformImageSbom` error, and that error already names the image and platform (`unable to converge sbom for image %q (platform %s)`).

**Rationale**: The signing spec (016) designed the guard as a single predicate precisely so that the C12 fix flips it. The signer is already plumbed per platform: `convergePlatformImageSbom → sbomStep.ConvergeWithMerge(..., signer, signerIdentity) → PushSBOM(..., signer)`. The zero-signature rejection (016 FR-009) lives below `PushSBOM` and applies per platform unchanged.

**Alternatives considered**: Keeping the function returning `true` (rejected: dead indirection, AGENTS.md simplicity rule); continue-and-aggregate on signing failure (rejected by customer clarification — the key is shared, failures are systemic).

**Note**: The per-image-name converge tasks run in parallel (`parallel.DoTasks`); "fail-fast" is per image name — parallel siblings finish their current step. This matches how any converge error behaves today; no new machinery.

## R2. Verify-all placement and flow

**Decision**: Extend `pkg/attestation` with an index-aware verification entry point (e.g. `VerifyIndex`) returning per-platform results; keep `cmd/werf/attest/verify` as thin wiring. Flow in `runVerify`:

- `--platform` given → `artifact.ResolvePlatformDigest` + single `attestation.Verify` (unchanged).
- No `--platform` → `artifact.ListIndexPlatforms(ctx, repo, digest)`:
  - non-index (single entry, empty Platform) → single `attestation.Verify` (unchanged, incl. stdout predicate dump);
  - index → per-platform verification loop + aggregate verdict.

**Rationale**: Constitution boundary — no business logic in `cmd/`. `attest ls` already uses exactly this expansion (`ls.go:118`), and `ListIndexPlatforms` already skips `unknown/unknown` entries (`platform.go:154`, covered by `platform_test.go`), satisfying the spec's exclusion of buildx attestation manifests.

**Alternatives considered**: Loop in the cmd layer (rejected: constitution); reusing `attestation.Verify` N times from cmd with ad-hoc error collection (rejected: classification logic below belongs in one place with unit tests).

## R3. Failure classification mechanism (missing / unsigned-legacy / invalid)

**Decision**: Classify inside the per-platform verification using existing primitives:

1. **missing** — `pullAttestationContent` (`get.go`) fails with `artifact.ErrNotFound` (typed sentinel, `fallback.go:403`, wrapped by `GetAttachedContent`/`GetAttachedContentAny`); detect via `errors.Is`.
2. **present but unsigned (legacy bare-DSSE)** — envelope pulled, `attestation.HasSignatures(envelopeJSON)` (`dsse.go:108`) returns false; report with the rebuild-with-key hint.
3. **invalid signature** — `HasSignatures` true but `VerifyDSSE` fails (also covers predicate-type mismatch and unwrap errors as verification failures with their own messages).

**Rationale**: All three predicates already exist and are unit-tested; no new formats or sniffing. `pullAttestationContent` already tries bundle first, bare-DSSE second (FR-010 dual-format read path holds inside verify-all for free).

**Alternatives considered**: Content sniffing on artifact bytes (rejected: 016 FR-006 forbids it — format detection is by descriptor artifactType, already how `pullAttestationContent` works); treating unsigned-legacy as missing or invalid (rejected by customer clarification).

## R4. Verify-all output contract

**Decision**: In verify-all (index, no `--platform`) mode, print a per-platform result table to stdout (PLATFORM / DIGEST / STATUS, mirroring the `attest ls` tabwriter style) and exit non-zero if any platform is not `verified`, with an aggregate error naming each failing platform and its classification. The raw predicate dump to stdout remains ONLY for single-target verification (non-index reference, or `--platform` given) — unchanged from today.

**Rationale**: Dumping N concatenated JSON predicates is not parseable and breaks the existing single-predicate stdout contract. The single-target contract is preserved byte-for-byte; verify-all is a new mode with no existing consumers (the command previously hard-failed on index refs via `ErrIndexPlatformRequired`, and the whole `attest` tree is `Hidden: true` — spec 008).

**Alternatives considered**: Dump all predicates (rejected: ambiguous stream); JSON report mode (deferred — no requirement; can be added later without breaking the table).

## R5. E2E strategy

**Decision**: Add a signed multi-platform scenario to `test/e2e/sbom/` (new file or extension of `signing_test.go`), labeled `Label("e2e", "sbom", "sbom-signing", "multiplatform", "simple")` so it runs in the `e2e_simple` CI job (both existing suites carry `simple`). Reuse existing helpers: `buildTrustedBuilderBase`, `generateSigningKeyPairWithCert` (signing_test.go), two-platform fixtures and registry inspection helpers (multiplatform_test.go). Verification assertions run in-process (`attestation.LoadVerifiers` + `VerifyDSSE`); `runCosignOfflineVerify` stays optional-when-available (cosign is not installed in CI). Negative verify-all scenarios manipulate the registry (delete one platform's artifact / rebuild one platform unsigned) and assert the aggregate error text.

**Rationale**: CI already runs `multiplatform`-labeled tests (QEMU/binfmt working) and `sbom-signing` tests in `e2e_simple`; combining labels needs no workflow changes. SC-002's full stock-cosign proof is done manually once, mirroring the 016 precedent.

**Alternatives considered**: New CI job with cosign installed (rejected: out of scope, existing precedent suffices).

## R6. Cache and checksum

**Decision**: No changes. `calculateStableChecksum` (`pkg/build/sbom_step.go:154`) already appends `signerIdentity` and `targetPlatform` as independent components; removing the guard makes `signerIdentity` non-empty for multi-platform builds, which is exactly the desired cache miss on first signed build (US4). Golden checksum tests from both parent features must keep passing unmodified (FR-008).

**Rationale**: Both parent specs designed the checksum for this composition; touching it would break their byte-identity guarantees.

## R7. Existing tests affected

**Decision**: `test/e2e/sbom/signing_test.go:50` asserts the absence of the "not yet supported" warning on a single-platform build — remains valid after warning removal. Unit tests referencing `sbomSigningSupported` — none found (grep over `pkg/` and `test/`); the guard is only called from `convergeImageSbom`. `attest verify` e2e/unit coverage for `ErrIndexPlatformRequired` on index refs: `pkg/oci/artifact/platform_test.go` tests `ResolvePlatformDigest` (unchanged — still used with `--platform` and by `get`); any test asserting `attest verify` fails on an index without `--platform` must be updated to the verify-all contract (to be located during implementation; `test/e2e/sbom/multiplatform_test.go` exercises `sbom get`/`attest` strict errors).
