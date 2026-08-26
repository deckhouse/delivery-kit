# Tasks: Signing of Multi-Platform SBOMs

**Input**: Design documents from `/specs/018-sbom-multiplatform-signing/`

**Prerequisites**: plan.md, spec.md (clarified 2026-08-19), research.md (R1–R7), data-model.md, contracts/

**Tests**: Included — mandated by constitution principle IV and spec SC-001…SC-006.

**Organization**: Tasks grouped by user story. US1 (build signing) and US2 (verify-all) are independent of each other; US3/US4 validate against US1's output.

## Format: `[ID] [P?] [Story] Description`

- **[P]**: Can run in parallel (different files, no dependencies)
- **[Story]**: US1–US4 from spec.md
- Exact file paths in every description

## Path Conventions

- **CLI commands**: `cmd/werf/attest/verify/`
- **Business logic**: `pkg/build/`, `pkg/attestation/`
- **Unit tests**: co-located `*_test.go` (Ginkgo + Gomega, DescribeTable preferred)
- **E2E tests**: `test/e2e/sbom/`

## Build & Test Commands

- **Build**: `task build` (produces `./bin/werf`)
- **Unit**: `task test:unit paths="./pkg/attestation/..."` (never `KEY=VALUE` after `--`)
- **E2E**: `task test:e2e paths="./test/e2e/sbom/..." labelFilter="sbom && (sbom-signing || multiplatform)"` — environment pre-configured, do not skip
- **Gates order**: `task format` → `task build` → `task lint` → `task test:unit` (format first — it mutates files)

---

## Phase 1: Setup

**Purpose**: Branch and baseline.

- [X] T001 Create branch `feat/sbom/sign-multiplatform-sbom` from up-to-date `origin/main` (read `.agents/skills/git-conventions/SKILL.md` first); move the untracked `specs/018-sbom-multiplatform-signing/` artifacts onto it
- [X] T002 Verify baseline: `task build` and `task test:unit paths="./pkg/attestation/... ./pkg/build/... ./pkg/oci/..."` pass on the clean branch before any change

---

## Phase 2: Foundational

**Purpose**: None required — no shared blocking prerequisites. US1 touches `pkg/build`, US2 touches `pkg/attestation` + `cmd/werf/attest/verify`; they are disjoint and independently mergeable increments on the same branch.

*(no tasks)*

---

## Phase 3: User Story 1 — Multi-platform build publishes a signed SBOM per platform (P1)

**Goal**: Remove the capability guard; every platform's SBOM is signed with the shared signer; signing failure fails the build fail-fast naming image+platform.

**Independent Test**: Two-platform build with `WERF_SIGN_KEY`/`WERF_SIGN_CERT` against the test registry → each platform manifest digest carries one signed Sigstore Bundle with subject = that digest; no warning; nothing on the index digest.

- [X] T003 [US1] Remove `sbomSigningSupported` (line 408) and the guard/warning branch in `convergeImageSbom` (lines 316–323) in `pkg/build/build_phase.go`: when `phase.SbomSigningOptions.Enabled`, always set `signer`/`signerIdentity`; delete the now-unused warning string; grep confirms zero remaining `sbomSigningSupported` hits (AGENTS.md rename/removal rule). FR-004 coverage note: fail-fast is the existing sequential loop in `convergeImageSbom` returning the first `convergePlatformImageSbom` error, the image+platform error naming is the existing wrap `unable to converge sbom for image %q (platform %s)` (`build_phase.go:395`), and the zero-signature rejection below `PushSBOM` is covered by existing 016-sbom-signing unit tests — no new code paths are introduced for FR-004, so no new test is required; the inherited coverage is re-executed in T013
- [X] T004 [US1] Add signed multi-platform e2e scenario in `test/e2e/sbom/signing_test.go` (or sibling `signing_multiplatform_test.go` if the file grows unwieldy) with `Label("e2e", "sbom", "sbom-signing", "multiplatform", "simple")`: reuse `buildTrustedBuilderBase` + `generateSigningKeyPairWithCert` + two-platform fixture pattern from `test/e2e/sbom/multiplatform_test.go`; assert per contract `contracts/build-signing.md`: (a) each platform manifest digest has exactly one bundle artifact (`application/vnd.dev.sigstore.bundle.v0.3+json`) with signed DSSE (`attestation.HasSignatures` true) verifying via `attestation.LoadVerifiers` + `VerifyDSSE`, (b) in-toto subject = platform manifest digest per platform, (c) build output does NOT contain "multi-platform SBOM signing is not yet supported", (d) index digest fallback tag has no attached SBOM artifact, (e) optional `runCosignOfflineVerify` per platform when cosign binary available
- [X] T005 [US1] Run `task test:e2e paths="./test/e2e/sbom/..." labelFilter="sbom && sbom-signing"` on Linux; then verify the new test per `.agents/skills/test-the-tests/SKILL.md` (mutation: restore the guard → the new scenario must fail)

**Checkpoint**: US1 delivers the MVP — signed multi-platform SBOMs, verifiable per platform with cosign/`--platform` (existing single-target verify path).

---

## Phase 4: User Story 2 — `attest verify` on an index verifies all platforms by default (P1)

**Goal**: Index reference without `--platform` → verify every platform, classify failures (verified/missing/unsigned/invalid), aggregate verdict; single-target modes byte-identical.

**Independent Test**: `werf attest verify --repo <repo> --type cyclonedx --key <pub> --tag <index-tag>` without `--platform` on a signed two-platform image → exit 0 with per-platform table; after making one platform's attestation unavailable (fallback-tag overwrite) → non-zero exit naming that platform as `missing`.

- [X] T006 [P] [US2] Add index-aware verification to `pkg/attestation/verify.go`: exported entry point (e.g. `VerifyIndex(ctx, repo, indexDigest, imageName, predicateType string, verifiers []signature.Verifier) ([]PlatformVerifyResult, error)`) looping `artifact.ListIndexPlatforms` entries; result type + type-name-prefixed string status constants per `data-model.md` (verified/missing/unsigned/invalid, no `iota`); classification per research R3: `errors.Is(err, artifact.ErrNotFound)` → missing, `HasSignatures` false → unsigned, `VerifyDSSE`/type-mismatch error → invalid; compile-time interface checks not needed (no interfaces); ctx first, errors wrapped
- [X] T007 [P] [US2] Add co-located unit tests `pkg/attestation/verify_index_test.go` (Ginkgo `DescribeTable`): matrix of 4 statuses × artifact formats (bundle, legacy bare-DSSE) using existing test key material helpers (see `pkg/attestation/dsse_test.go`, `bundle_test.go`); assert aggregate rule (all verified → success; each failure names platform + classification)
- [X] T008 [US2] Wire verify-all in `cmd/werf/attest/verify/verify.go` per `contracts/attest-verify-cli.md`: when `platformFlag == ""`, probe with `artifact.ListIndexPlatforms`; non-index → existing single path unchanged (incl. predicate dump to stdout); index → call the new `pkg/attestation` entry point, render tabwriter table `PLATFORM\tDIGEST\tSTATUS` (style of `cmd/werf/attest/ls/ls.go`), return aggregated error on any non-verified platform; keep `--platform` path via `ResolvePlatformDigest` untouched; update `--platform` flag help text (no longer required for index refs on `verify`)
- [X] T009 [US2] Run `task doc:gen` to regenerate CLI reference for the changed `verify` help text (`docs/_includes/reference/cli/`, `docs/pages_en/reference/cli/`)
- [X] T010 [US2] Add verify-all e2e scenarios to the signed multi-platform test from T004 in `test/e2e/sbom/signing_test.go` (labels already cover it): (a) verify-all on index tag → success, both platforms in table; (b) wrong key → failure, both platforms `invalid`; (c) make one platform's attestation unavailable WITHOUT the registry DELETE API (stock `registry:2` rejects DELETE unless `REGISTRY_STORAGE_DELETE_ENABLED=true` — AGENTS.md): overwrite that platform's `sha256-<hex>` fallback tag with an empty artifact index (tag push works on any registry) → failure classifying that platform `missing` while the other is `verified`; (d) `--platform linux/arm64` → single-platform predicate dump unchanged
- [X] T011 [US2] Smoke-test the real binary (unit suite cannot catch wiring SIGSEGVs — AGENTS.md): `task build`, then run `./bin/werf attest verify --repo <test-registry-repo> --type cyclonedx --key <pub.pem> --tag <index-tag>` against the e2e registry once; then apply `.agents/skills/test-the-tests/SKILL.md` to T010 (mutation: classify unsigned as verified → tests must fail)

**Checkpoint**: US2 complete — "signed with one key, verified with one command".

---

## Phase 5: User Story 3 — Existing behavior preserved (P2)

**Goal**: Single-platform (signed/unsigned) and unsigned multi-platform behavior byte-identical; strict `--platform` on `get` commands intact.

**Independent Test**: Both parent e2e suites pass unmodified; golden checksum unit tests pass unmodified.

- [X] T012 [US3] Locate and reconcile tests asserting the OLD `attest verify` index behavior (research R7): grep `test/` and `pkg/` for assertions that `attest verify` without `--platform` fails on an index (e.g. in `test/e2e/sbom/multiplatform_test.go`); update ONLY `verify`-related assertions to the verify-all contract; assertions for `attest get`/`sbom get` strict `--platform` errors MUST remain untouched
- [X] T013 [US3] Run regression gates: `task test:unit paths="./pkg/build/... ./pkg/attestation/... ./pkg/oci/..."` (golden checksum tests from both parent features pass unmodified — FR-008; the 016 zero-signature rejection unit tests pass — inherited FR-004 evidence per T003) and `task test:e2e paths="./test/e2e/sbom/..." labelFilter="sbom && (multiplatform || sbom-signing)"` (unsigned MP scenario asserts bare-DSSE + no warning; single-platform signed/unsigned scenarios byte-form identical)

---

## Phase 6: User Story 4 — Cache correctness (P2)

**Goal**: Unchanged signed rebuild hits cache per platform; enabling key / rotating key misses for all platforms and supersedes stale bare-DSSE.

**Independent Test**: Rebuild sequences against the test registry observing "Use previously generated SBOM from registry" log lines and artifact supersede.

- [X] T014 [US4] Extend the T004 e2e scenario in `test/e2e/sbom/signing_test.go` with cache assertions: (a) immediate rebuild with same key → both platforms log "Use previously generated SBOM from registry", no re-publish; (b) start from an unsigned MP build, rebuild with key → cache miss for both platforms, signed bundles supersede stale bare-DSSE entries per fallback-index replace semantics (assert bare-DSSE descriptor gone, bundle present); (c) rebuild with a rotated key → cache miss for both platforms
- [X] T015 [US4] Re-run `task test:e2e paths="./test/e2e/sbom/..." labelFilter="sbom && sbom-signing && multiplatform"` after T014 (constitution: re-execute after every change)

---

## Phase 7: Polish & Cross-Cutting

- [X] T016 Full verification sequence per `quickstart.md`: `task format` → `task build` → `task lint` → `task test:unit` (unscoped) → full sbom e2e labels; fix anything introduced by this feature only
- [X] T017 Manual stock-cosign check (SC-002, once): per `quickstart.md` — `cosign verify-attestation --new-bundle-format --insecure-ignore-tlog=true --key pub.pem --type cyclonedx --platform <p> <index-ref>` passes for each platform and fails with a wrong key; record the transcript in `specs/018-sbom-multiplatform-signing/` notes
- [X] T018 Scoped diff hygiene: `git diff --check` on authored files only (NOT repo-wide — generated CLI docs carry trailing whitespace); confirm no comments violating AGENTS.md were added; grep zero hits for `sbomSigningSupported` and the removed warning string

---

## Dependencies

```text
Phase 1 (T001–T002)
  ├─→ Phase 3 / US1 (T003–T005) ──┐
  └─→ Phase 4 / US2 (T006–T011) ──┤   US1 ∥ US2 (disjoint files; T010's registry fixtures need T003 merged
                                   │   on the branch, so finish T003 before running T010's e2e)
                                   ├─→ Phase 5 / US3 (T012–T013)
                                   ├─→ Phase 6 / US4 (T014–T015, needs US1)
                                   └─→ Phase 7 (T016–T018)
```

- US1 (P1) and US2 (P1) are independently implementable; US2's e2e (T010) exercises artifacts produced by US1's build path.
- US3 and US4 are validation-heavy stories on top of US1/US2 outputs.

## Parallel Execution Examples

- **After T002**: T003 (build_phase.go) ∥ T006+T007 (pkg/attestation) — disjoint packages.
- **Within US2**: T006 ∥ T007 (source vs test file skeleton) then T008 sequentially (depends on T006's API).
- **E2E runs** (T005, T010, T013, T015) are sequential on the Linux runner — shared registry state.

## Implementation Strategy

**MVP = Phase 1 + US1 (T001–T005)**: signed per-platform SBOMs are immediately valuable and verifiable with existing single-target `attest verify --platform` and stock cosign. US2 upgrades the verification UX; US3/US4 lock regressions and cache semantics. Deliver as one PR (`.agents/skills/pull-request/SKILL.md`, draft by default), commits per `.agents/skills/git-conventions/SKILL.md` (`feat(sbom): ...`, `feat(attest): ...`).
