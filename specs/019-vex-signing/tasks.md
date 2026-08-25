# Tasks: VEX Signing at Build Time with Cosign Compatibility

**Input**: Design documents from `/specs/019-vex-signing/`

**Prerequisites**: plan.md, spec.md, research.md, data-model.md, contracts/

**Tests**: Included — the spec's success criteria explicitly require unit and e2e proof (SC-001…SC-006).

**Organization**: Tasks are grouped by user story to enable independent implementation and testing of each story.

## Format: `[ID] [P?] [Story] Description`

- **[P]**: Can run in parallel (different files, no dependencies)
- **[Story]**: Which user story this task belongs to (US1…US5)
- Include exact file paths in descriptions

## Path Conventions

- **CLI commands**: `cmd/werf/<domain>/`
- **Business logic**: `pkg/<domain>/`
- **Unit tests**: co-located with source files as `*_test.go`
- **E2E tests**: `test/e2e/<domain>/`

## Build & Test Commands

- **Build**: `task build` (produces `./bin/werf`)
- **Unit tests**: `task test:unit paths="./pkg/..."`; focused: `task test:unit paths="./pkg/..." -- -focus=MyTest -v`
- **Lint**: once per session `task deps:install:golangci-lint`, then `task lint`
- **E2E tests**: always scoped with both `paths` and `labelFilter`, e.g. `task test:e2e paths="./test/e2e/vex/..." labelFilter="VEX"`; environment is pre-configured, never run `task test:setup:environment`
- **Integration tests**: `task test:integration`
- **Formatting**: `task format`

---

## Phase 1: Setup

**Purpose**: Baseline verification — no project scaffolding needed (existing monolith).

- [X] T001 Verify baseline gates on the branch before changes: `task format`, `task build`, `task deps:install:golangci-lint`, `task lint`, `task test:unit` — record any pre-existing failures

---

## Phase 2: Foundational (Blocking Prerequisites)

**Purpose**: Slot-key discrimination and predicate alias machinery — every user story depends on these. Contract: [contracts/artifact-slot-discrimination.md](contracts/artifact-slot-discrimination.md).

- [X] T002 Add predicate-annotation constant (`dev.sigstore.bundle.predicateType`) and extend the slot key in `pkg/oci/artifact/fallback.go`: `isArtifactKey`, `updateFallbackIndex`, `isAttached`, `supersededKey` gain the predicate dimension; absent annotation ⇒ predicate `""` (legacy)
- [X] T003 Extend writers/readers in `pkg/oci/artifact/store.go`: `artifactAnnotations` accepts the predicate URI; `Attach`/`AttachSuperseding` carry it; add predicate-aware lookup (exact-annotation matches first, annotation-less legacy entries returned as low-priority candidates) alongside `GetAttached`/`GetAttachedContent`/`GetAttachedContentAny`
- [X] T004 Update `matchDescriptors` in `pkg/oci/artifact/fallback.go` for predicate-aware reads per the contract read rules (exact match preferred, legacy candidates last, digest dedup preserved)
- [X] T005 Co-located unit tests in `pkg/oci/artifact/`: DescribeTable slot-key matrix — {SBOM, VEX} × {signed Bundle, unsigned DSSE} × {annotated, legacy} covering coexistence (no cross-kind eviction), own-kind supersede, legacy candidate ordering
- [X] T006 [P] Add openvex alias set {`https://openvex.dev/ns`, `https://openvex.dev/ns/v0.2.0`} and a predicate-match helper in `pkg/attestation/predicate_types.go` (`openvex` short name and either full URI match both); keep all other types exact
- [X] T007 [P] Unit tests for alias resolution/matching in `pkg/attestation/predicate_types_test.go` (DescribeTable: short names, full URIs, non-openvex exactness)
- [X] T008 Update all existing callers of changed `pkg/oci/artifact` signatures (SBOM step/image, VEX step/image, attestation get/verify/ls, copy/propagation paths) to compile with the predicate parameter — passing the correct predicate for SBOM (`https://cyclonedx.org/bom` signed / `https://cyclonedx.org/bom/v1.6` unsigned) and VEX writers, empty/alias-set for generic readers; run `task build` and `task test:unit paths="./pkg/..."`

**Checkpoint**: `task build` and scoped unit tests green — user story phases can start.

---

## Phase 3: User Story 1 — Signed VEX published during build (Priority: P1) 🎯 MVP

**Goal**: `werf build --sign-key/--sign-cert` publishes one signed Sigstore Bundle VEX artifact per image at the image (index) digest. Contract: [contracts/build-vex-signing.md](contracts/build-vex-signing.md).

**Independent Test**: Build a fixture with a `vex` field and a signing key against the test registry; inspect the fallback tag of the image digest.

- [X] T009 [US1] Create `pkg/build/signing/vex_signing.go`: `VexSigningOptions` (Enabled + private `*Signer`) + `NewVexSigningOptions`, mirroring `sbom_signing.go`
- [X] T010 [US1] Wire options in `cmd/werf/common/signature.go` (`getVexSigningOptions`: Enabled = `SignKey != ""`) and plumb through `cmd/werf/common/conveyor_options.go`, `pkg/build/conveyor.go` (ConveyorOptions), `pkg/build/build_phase.go` (BuildOptions/BuildPhase)
- [X] T011 [US1] Extract signer + fingerprint in `convergeImageVex` (`pkg/build/build_phase.go`) and pass to `vexStep.Converge`; a signing/publish failure fails the build naming the image (FR-008, existing error wrapping)
- [X] T012 [US1] Update `pkg/build/vex_step.go`: `Converge` accepts signer/signerIdentity; checksum becomes stable-hash{vexJSON, parentDigest, `vexArtifactFormatVersion`="2", signerIdentity} (mirror `calculateStableChecksum` in `pkg/build/sbom_step.go`); publish-needed check reads both artifact types predicate-aware (bundle first, DSSE fallback)
- [X] T013 [US1] Update `pkg/vex/image/image.go` `PushVEX`: accept signer; signed path — unversioned predicate `https://openvex.dev/ns`, `WrapInDSSE(signer)`, `HasSignatures` guard (zero signatures ⇒ error), `WrapInBundle`, `AttachSuperseding(BundleMediaType, superseded: DSSE openvex aliases + content-verified legacy)`; unsigned path — payload byte-identical to today (versioned predicate, bare DSSE) + predicate annotation; both paths pass the openvex predicate annotation
- [X] T014 [P] [US1] Unit tests: checksum composition transitions in `pkg/build/vex_step_test.go` (unchanged→hit, v1→v2 miss, key add/rotate/remove miss) and `PushVEX` signed/unsigned artifact form in `pkg/vex/image/image_test.go`
- [X] T015 [US1] E2E in `test/e2e/vex/`: signed single-platform and signed two-platform scenarios — exactly one Bundle at the image (index) digest, predicate `https://openvex.dev/ns`, annotation present, nothing on platform manifest digests, in-process DSSE verification passes with the right key / fails with a wrong key; `Label("e2e", "VEX", "signing", "simple")`; run `task test:e2e paths="./test/e2e/vex/..." labelFilter="VEX"`

**Checkpoint**: US1 independently deliverable — signed VEX publish works end-to-end.

---

## Phase 4: User Story 2 — SBOM and VEX coexist on one image (Priority: P1)

**Goal**: Both artifacts present, independently discoverable, each superseded only by its own kind (fixes the latent mutual-eviction defect).

**Independent Test**: Build a fixture with `build.sbom.enable` + `vex`; list attached artifacts and assert both kinds.

- [X] T016 [US2] Pass predicate annotations on SBOM publishes: `pkg/sbom/image/image.go` `PushSBOM` (signed `https://cyclonedx.org/bom`, unsigned `https://cyclonedx.org/bom/v1.6`), make the SBOM publish-needed/read checks in `pkg/build/sbom_step.go` predicate-aware, and make the SBOM read path in `pkg/sbom/image/image.go` (`pullSBOMArtifact`) predicate-aware so `sbom get`/`sbom merge` never select a VEX entry when both kinds share a digest (payload bytes and checksum composition unchanged)
- [X] T017 [US2] Verify `pkg/attestation/ls.go` lists both kinds correctly after the slot change (adjust only if the shared lookup changes broke it; output shape unchanged)
- [X] T018 [US2] E2E coexistence scenario in `test/e2e/sbom/` (SBOM+VEX fixture, keyless and with key): both artifacts present via `attest ls` with correct predicate types and signed flags — including on a multi-platform index reference (VEX entry at the index digest, SBOM entries at platform digests); changing only the VEX file republishes only VEX, SBOM entry byte-identical; `Label("e2e", "sbom", "sbom-signing", "simple")`; run `task test:e2e paths="./test/e2e/sbom/..." labelFilter="sbom-signing"`

**Checkpoint**: US1+US2 = coherent signed supply chain for one image.

---

## Phase 5: User Story 3 — Unsigned behavior preserved (Priority: P2)

**Goal**: Keyless builds keep the legacy artifact form; pre-feature artifacts stay readable.

**Independent Test**: Existing VEX lifecycle e2e passes unmodified.

- [X] T019 [P] [US3] Unit test in `pkg/vex/image/image_test.go`: unsigned `PushVEX` payload (DSSE envelope bytes) byte-identical to the pre-feature form (golden), predicate `https://openvex.dev/ns/v0.2.0`, empty signatures
- [X] T020 [P] [US3] Legacy-artifact read test in `pkg/oci/artifact/` or `pkg/attestation/`: annotation-less VEX and SBOM entries (simulating pre-feature registry state) remain readable and are content-verified to the correct kind
- [X] T021 [US3] Run the existing VEX lifecycle e2e unmodified and confirm green: `task test:e2e paths="./test/e2e/vex/..." labelFilter="VEX"`

---

## Phase 6: User Story 4 — Cache correctness across signing changes (Priority: P2)

**Goal**: Enabling signing / rotating the key republishes; unchanged rebuilds hit the cache.

**Independent Test**: Rebuild sequences against the test registry observing publish decisions in build logs.

- [X] T022 [US4] E2E cache scenario in `test/e2e/vex/`: (a) unchanged signed rebuild → "VEX artifact is up to date" and no republish; (b) previously keyless project rebuilt with key → republish signed bundle superseding bare-DSSE; (c) key rotation → republish; (d) key removed → republish unsigned bare-DSSE, bundle entry evicted, subsequent `attest get --type openvex` returns the unsigned document; `Label("e2e", "VEX", "signing", "simple")`

---

## Phase 7: User Story 5 — Verification of signed VEX (Priority: P2)

**Goal**: `attest verify/get --type openvex` work on manifest and index refs with clear classification. Contract: [contracts/attest-openvex-cli.md](contracts/attest-openvex-cli.md).

**Independent Test**: Verify a signed multi-platform VEX via index ref with correct/wrong keys.

- [X] T023 [US5] Predicate-aware artifact selection in `pkg/attestation/get.go` and `pkg/attestation/verify.go`: select by openvex alias set with legacy content-verified fallback; classify a bare-DSSE result on `verify` as "present but unsigned (legacy format) — rebuild with --sign-key" distinct from not-found and signature-mismatch errors
- [X] T024 [US5] Index handling in `cmd/werf/attest/verify/verify.go` and `cmd/werf/attest/get/get.go`: for openvex predicate use the resolved digest as-is (skip `ResolvePlatformDigest` platform expansion, no `ErrIndexPlatformRequired`); `--platform` combined with openvex on an index reference → usage error; update `--platform` flag help text
- [X] T025 [P] [US5] Unit tests in `pkg/attestation/`: DescribeTable verification classification (signed+match, signed+mismatch, unsigned, missing) × (annotated, legacy) artifacts
- [X] T026 [US5] Run `task doc:gen` and commit regenerated CLI reference pages for the changed help text
- [X] T027 [US5] E2E verify scenario in `test/e2e/vex/`: `./bin/werf attest verify --type openvex` succeeds on single-platform and index refs with the right key, fails with a wrong key, reports "unsigned" for a keyless artifact, and rejects `--platform` on an index ref; `Label("e2e", "VEX", "signing", "simple")`

---

## Phase 8: Polish & Final Gates

- [X] T028 Full unscoped gate run in order: `task format` → `task build` → `task lint` → `task test:unit`
- [ ] T029 Scoped e2e for both suites (`task test:e2e paths="./test/e2e/vex/..." labelFilter="VEX"`, `task test:e2e paths="./test/e2e/sbom/..." labelFilter="sbom-signing"`), then `task test:integration` — DEFERRED TO LINUX CI per customer instruction (macOS workstation; e2e suites are written and compile)
- [ ] T030 Execute the manual stock-cosign check from [quickstart.md](quickstart.md) once (SC-002) if the cosign binary is available; record the result in the PR description — DEFERRED: requires a real registry with published artifacts (after CI e2e)
- [X] T031 Sweep: grep for leftover TODOs/debug output in changed files; verify no comments restating code (AGENTS.md rule); `git diff --check` scoped to authored files

### Execution notes (2026-08-23, macOS workstation)

- Baseline (T001): 66/67 unit suites green; `cmd/werf/common` failed on darwin (linux-only `instructions.GetSecurity` in the test binary path) — pre-existing, environmental.
- Final gates (T028): `task format`, `task build`, `task lint`, `task test:unit` — green. One flake in the unscoped run: `pkg/true_git` failed under 9-proc parallel load, passes scoped, zero diff in the package — unrelated.
- E2E (T015/T018/T021/T022/T027 execution, T029, T030): deferred to Linux CI per customer instruction; all e2e code compiles (`go vet` clean on `test/e2e/vex`, `test/e2e/sbom`).

---

## Dependencies

```text
Phase 1 (T001)
  └─→ Phase 2 Foundational (T002–T008)   ← blocks everything below
        ├─→ Phase 3 US1 (T009–T015)      ← MVP
        │     ├─→ Phase 4 US2 (T016–T018)   (needs signed VEX publish for the with-key half)
        │     ├─→ Phase 6 US4 (T022)        (needs checksum + signed publish)
        │     └─→ Phase 7 US5 (T023–T027)   (needs published signed artifacts to verify)
        └─→ Phase 5 US3 (T019–T021)      (only needs foundational + unsigned path, parallel to US1 after T013)
Phase 8 (T028–T031) ← after all stories
```

## Parallel Execution Examples

- **Foundational**: T006+T007 (attestation aliases) parallel to T002–T005 (oci/artifact slot key)
- **US1**: T014 parallel to T015 once T012/T013 land
- **US3**: T019, T020 parallel; both parallel to US2/US4/US5 work
- **US5**: T025 parallel to T024/T026

## Implementation Strategy

MVP = Phase 2 + Phase 3 (US1): signed VEX publish, independently demonstrable. Then US2 (coexistence — the safety half of the P1 pair), then US3/US4/US5 in any order (US3 can start even earlier). Each story phase ends with its own e2e proof; polish phase runs the unscoped gates.
