# Implementation Plan: SBOM Signing at Build Time with Cosign Compatibility

**Status**: migrated (reverse-engineered from the executed work plan and the actual diff)

**Branch**: `feat/sbom/sign-sbom-at-build` — 16 commits on top of `origin/main` (incl. review-feedback commits)

## Technical Context

| Aspect | Choice |
|---|---|
| Language / framework | Go; Ginkgo/Gomega for tests (repo standard) |
| Signing primitives | `github.com/sigstore/sigstore/pkg/signature` (already a dependency); DSSE PAE via `go-securesystemslib/dsse` |
| Signer source | `delivery-kit-sdk/pkg/signver.SignerVerifier` (embeds sigstore `signature.SignerVerifier`) wrapped by `pkg/build/signing.Signer` — no adapter needed |
| Bundle format | Sigstore Bundle v0.3, hand-built JSON structs (NO sigstore-go / protobuf-specs dependencies — air-gapped constraint) |
| Ground truth | Live cosign v2.5.3 experiment against an in-memory registry established the exact target shape (bundle fields, hint derivation, offline verify recipe) and settled that cosign accepts `Statement/v1`; the captured cosign-produced bundle is the golden test fixture (`pkg/attestation/testdata/cosign-golden-bundle.json`) |
| Storage | Existing OCI referrers fallback-tag index (`sha256-<hex>`), extended with cross-type supersede |

## Key Technical Decisions

1. **Gate by key presence**: `signature.ResolveSigningGate` (pkg/signature/signing_gate.go) is the single source of truth — SBOM signing enables on `--sign-key`, manifest/ELF keep their explicit flags; key+cert validation lives only there, `cmd/werf/common/signature.go` delegates. Lives in the existing `pkg/signature` domain package (review feedback).
2. **Narrow signer interface downstream**: `ConvergeWithMerge`/`PushSBOM` accept sigstore `signature.Signer`; the full `signing.Signer` stays at the BuildPhase level.
3. **Format switch only on the signed path**: unsigned builds keep bare DSSE + versioned predicateType byte-for-byte; signed builds switch artifactType and drop the predicateType version suffix (cosign convention).
4. **Dual-format read by descriptor artifactType** (bundle first, DSSE fallback), never content sniffing — O(1) branching, no format-guessing framework.
5. **Cross-type supersede inside the converge loop**: `AttachSuperseding` threads `supersededTypes` into the fallback-index convergence — superseded entries are part of the `isAttached` predicate, so publishing a bundle removes the stale bare-DSSE entry for the same image name and an interrupted attach self-heals on the next converge iteration.
6. **Cache identity**: format-version const (`sbomArtifactFormatVersion = "2"`) + public-key SHA-256 fingerprint appended to `calculateStableChecksum`. The fingerprint is computed once per build via `Signer.Fingerprint()` (`sync.Once`) and passed down as a string (review feedback: it was recomputed per image). Cert fingerprint deliberately excluded (bundle carries no cert; see spec "Documented Decisions").
7. **Multi-platform guard as capability function** (`sbomSigningSupported`) with a warning — flipped by the future C12 fix without touching the signing code.
8. **Fail-closed guards**: signer configured but zero signatures → error; signing error → build failure (no silent unsigned fallback).

## Project Structure (where the feature lives)

```
pkg/attestation/            bundle.go (+tests, golden fixture), dsse.go (consts consolidated),
                            get.go/ls.go (dual-format), statement.go (unchanged: Statement/v1)
pkg/signature/              signing_gate.go (gate, moved here per review) + tests
pkg/build/signing/          signer.go (Signer + cached Fingerprint), sbom_signing.go (options)
pkg/build/                  build_phase.go (signer wiring, multi-platform guard),
                            sbom_step.go (signer param, cache checksum, dual-type cache lookup)
pkg/sbom/image/             image.go (PushSBOM signed/unsigned split, dual-format pull),
                            dsse.go (ctx+signer pass-through, C13 fix)
pkg/oci/artifact/           fallback.go (supersede in converge loop), store.go (AttachSuperseding)
cmd/werf/common/            signature.go (gate delegation), conveyor_options.go (plumbing)
test/e2e/sbom/              signing_test.go + _fixtures/signing/ (label "sbom-signing";
                            keys via delivery-kit-sdk test/pkg/cert_utils, ed25519)
```

## Implementation Phases (as executed)

1. **Foundation** — media-type constant consolidation into `pkg/attestation`; signing gate + `SbomSigningOptions` plumbing to BuildPhase; live cosign `_type` experiment (verdict: KEEP v1).
2. **Core plumbing** — ctx+signer threaded through the SBOM path (nil-shim and `context.Background()` removed); hand-built Bundle serializer validated against the cosign golden fixture.
3. **Format switch** — signed publish path to bundle form with index supersede; dual-format read path; `attest ls/get/verify` bundle support.
4. **Cache + e2e** — checksum format version + signer identity; e2e round-trip suite (signed/unsigned/no-cert, optional real-cosign offline verify).
5. **Review feedback + rebase** — gate moved into `pkg/signature`; signer fingerprint cached via `sync.Once`; ed25519 made the primary tested key type; e2e reuses `delivery-kit-sdk` cert helpers; supersede ported onto the converge-style fallback index absorbed from main.

## Complexity Assessment

- 32 files changed, ~1390 insertions / ~145 deletions (after rebase onto the converged-index main and review feedback).
- No new module dependencies; no schema/config changes; no storage-layout changes beyond the artifactType of signed artifacts.

## Verification Performed

- Unit: TDD across all new logic (gate table tests, DSSE sign/verify round-trips incl. corrupted-signature rejection, bundle golden structural equality, checksum invalidation table).
- Live experiment: cosign v2.5.3, in-memory registry — both `Statement/v0.1` and `Statement/v1` PASS new-bundle verification (discriminating test).
- Manual end-to-end (macOS arm64, Docker, local registry:2, `--platform=linux/amd64`): signed build → index/manifest/blob inspection via crane → real cosign offline verify PASS → wrong-key FAIL → cache-hit rebuild → key-without-cert error → unsigned regression. Evidence: `.omo/evidence/F3-sbom-signing-qa.txt`.
- Quality gates: `task format` / `task build` / `task lint` / `task test:unit` green (one pre-existing `pkg/werf/exec` failure reproduced on clean main).
- e2e suite compiles (vet with e2e build tags); full run requires Linux CI.
