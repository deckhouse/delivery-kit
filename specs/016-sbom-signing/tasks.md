# Tasks: SBOM Signing at Build Time with Cosign Compatibility

**Status**: migrated — all tasks reflect work already completed on `feat/sbom/sign-sbom-at-build`

## Phase 1: Foundation

- [x] T001 Consolidate DSSE/in-toto media-type constants into `pkg/attestation` (single definition each; all callers reference the consts)
- [x] T002 Add `SbomSigningOptions` and `ResolveSigningGate` in `pkg/build/signing`; delegate `getSignerOptions` gate logic from `cmd/werf/common/signature.go`; plumb options `BuildOptions → ConveyorOptions → BuildPhase` (TDD: gate table tests incl. ELF dimension)
- [x] T003 Live cosign experiment: verify cosign v2.5.3 accepts `Statement/v1` in new-bundle attestations (verdict: KEEP v1, no constant change); capture cosign-produced golden bundle fixture

## Phase 2: Core plumbing

- [x] T004 Thread ctx+signer through `convergeImageSbom → ConvergeWithMerge → PushSBOM → attestation.WrapInDSSE`; remove nil-signer shim and `context.Background()`; add fail-closed guards (zero-signature detection, signing error fails build); multi-platform capability guard with warning (TDD: nil-signer regression, sign/verify round-trip, error-signer, corrupted-signature rejection)
- [x] T005 Hand-built Sigstore Bundle v0.3 serializer in `pkg/attestation/bundle.go`: `WrapInBundle`/`UnwrapBundle`, hint = base64(sha256(DER SPKI)) (TDD: round-trip, golden structural equality, error table; `go.mod` untouched)

## Phase 3: Format switch

- [x] T006 Signed publish path: wrap signed DSSE in bundle, artifactType → `application/vnd.dev.sigstore.bundle.v0.3+json`, predicateType → `https://cyclonedx.org/bom`; unsigned path unchanged; supersede stale bare-DSSE index entry (`AttachOptions.SupersededTypes`, `OCIStore.AttachSuperseding`)
- [x] T007 Dual-format read path by descriptor artifactType (bundle first, legacy DSSE fallback) in pull, cache lookup, and predicateType validation; `sbom merge` inherits transparently
- [x] T008 `attest ls/get/verify` support bundle artifacts (list both types, unwrap bundle before DSSE processing); commands stay hidden

## Phase 4: Cache + e2e

- [x] T009 Cache checksum: add `sbomArtifactFormatVersion` const and signer public-key fingerprint to `calculateStableChecksum` (TDD: invalidation table — signing enabled / key rotated / format bumped → miss; unchanged → hit)
- [x] T010 e2e suite `test/e2e/sbom/signing_test.go` (label `sbom-signing`): signed round-trip (index/bundle/signature asserts, `attest verify`, optional real-cosign offline verify), unsigned regression, key-without-cert failure; sigstore-encrypted key generation in the helper

## Post-review fixes

- [x] T011 Deduplicate `OCIStore.Attach`/`AttachSuperseding` (review finding: `Attach` now delegates)
- [x] T012 e2e helper: emit "ENCRYPTED DELIVERY-KIT PRIVATE KEY" PEM instead of plain PKCS#8 (manual QA finding: the SDK key loader always runs sigstore `encrypted.Decrypt`)
- [x] T013 Rebase onto fresh `origin/main` (import conflict with the `GetAttachedContentAny` auth fix resolved)

## Verification (final wave, all approved)

- [x] V001 Plan compliance audit — acceptance criteria re-verified from evidence and code
- [x] V002 Code quality review vs AGENTS.md/CODESTYLE.md (led to T011)
- [x] V003 Real manual QA: build → crane inspection → cosign offline verify PASS / wrong-key FAIL → cache hit → unsigned regression → no-cert error (`.omo/evidence/F3-sbom-signing-qa.txt`)
- [x] V004 Scope fidelity audit vs Must-NOT-Have list (no C12 changes, no new deps, no schema/docs, storage invariants intact)

## Gaps / Follow-ups

- ⚠️ **Multi-platform SBOM stays unsigned** — per-platform SBOM generation (C12) is broken independently of signing and is tracked separately (`.omo/docs/c12-multiplatform-sbom-context.md`); the guard is one capability function to flip.
- 📋 **Cert fingerprint excluded from cache identity — documented decision.** The bundle embeds only `publicKey.hint`, so a cert-only renewal yields a byte-identical artifact and a cache hit is correct. Revisit if certificates are embedded into `verificationMaterial`.
- 📋 **Manifest-level `artifactType` not set — pre-existing, cosmetic.** The vendored go-containerregistry mutate API has no setter for the top-level manifest field; cosign reads the type from the fallback-index descriptor and verification passes. OCI 1.1 SHOULD-level follow-up for the next change touching `pkg/oci/artifact`.
- 📋 **Duplicate annotation-less fallback-index entry** (go-containerregistry auto-referrers on push) — pre-existing on main, reproduced on the untouched unsigned path; addressed in a separate PR.
