---

description: "Task list for ELF Signing Anchor Digest"
---

# Tasks: ELF Signing Anchor Digest

**Input**: Design documents from `/specs/020-elf-signing-anchor-digest/`

**Prerequisites**: `plan.md`, `spec.md`, `research.md`, `data-model.md`, `contracts/anchor-digest.md`, `quickstart.md`

**Scope**: Extend the existing private anchor branch of `calculateDigest` with the stable, non-secret ELF signing identities already defined by the non-anchor checksum contract. No public API, CLI, dependency, storage schema, registry protocol, or cryptographic implementation changes are required.

## Phase 1: Setup (Shared Infrastructure)

**Purpose**: Confirm the existing implementation and test locations; this brownfield feature requires no project initialization or dependency changes.

- [X] T001 Confirm the existing digest implementation and co-located Ginkgo/Gomega test locations in `pkg/build/build_phase.go` and `pkg/build/content_digest_test.go` before modifying either file

---

## Phase 2: Foundational (Blocking Prerequisites)

**Purpose**: No new foundational code is required. The existing `pkg/build` digest path, signing option types, hashing helpers, and test harness provide all prerequisites.

**Checkpoint**: Existing build and test infrastructure is sufficient; user story work can proceed after T001.

---

## Phase 3: User Story 1 - Invalidate anchors when BSign identity changes (Priority: P1) 🎯 MVP

**Goal**: Make the anchor digest sensitive to the BSign key fingerprint while excluding private signing material from cache identity.

**Independent Test**: With BSign enabled and all other anchor inputs unchanged, two fingerprints produce different anchor digests and repeated calculations with one fingerprint are deterministic; changing only private key/passphrase fields while BSign is disabled leaves the digest unchanged.

### Tests for User Story 1

- [X] T002 [US1] Add Ginkgo/Gomega cases in `pkg/build/content_digest_test.go` that assert deterministic anchor digests for identical BSign fingerprints, changed digests for different `PGPPrivateKeyFingerprint` values, and unchanged digests when only private key/passphrase values change while BSign is disabled

### Implementation for User Story 1

- [X] T003 [US1] Update the anchor input assembly in `pkg/build/build_phase.go` to append `PGPPrivateKeyFingerprint` only when `ELFSigningOptions.Enabled()` and `BsignEnabled` are true, using the existing `ELF_SIGNING_PGP_KEY_FINGERPRINT` label and preserving input ordering

**Checkpoint**: User Story 1 is independently testable with `task test:unit paths="./pkg/build/..."`.

---

## Phase 4: User Story 2 - Invalidate anchors when in-house signing identity changes (Priority: P1)

**Goal**: Make the anchor digest sensitive to the in-house signing certificate and certificate chain when in-house signing applies.

**Independent Test**: With in-house signing enabled and all other anchor inputs unchanged, changing the certificate or chain independently produces a different anchor digest, while identical certificate and chain inputs remain deterministic.

### Tests for User Story 2

- [X] T004 [US2] Extend `pkg/build/content_digest_test.go` with Ginkgo/Gomega cases that assert deterministic anchor digests for identical in-house signer identities and changed digests when `ManifestSigningOptions.Signer().Cert()` or `.Chain()` changes independently

### Implementation for User Story 2

- [X] T005 [US2] Update the anchor input assembly in `pkg/build/build_phase.go` to append `ManifestSigningOptions.Signer().Cert()` and `.Chain()` only when `ELFSigningOptions.Enabled()` and `InHouseEnabled` are true, using the existing `MANIFEST_SIGNING_CERTIFICATE` and `SIGNING_CERTIFICATE_CHAIN` labels and preserving input ordering

**Checkpoint**: User Stories 1 and 2 are independently testable with `task test:unit paths="./pkg/build/..."`.

---

## Phase 5: User Story 3 - Keep anchor and non-anchor signing contracts aligned (Priority: P2)

**Goal**: Ensure anchor signing inputs use exactly the same conditions, labels, values, exclusions, and sign-stage coverage as the existing non-anchor checksum contract, without adding a signing-state marker.

**Independent Test**: Compare anchor and non-anchor digest behavior while varying each applicable fingerprint, certificate, and chain value; verify disabled or absent signing does not add a standalone marker, secrets are excluded, and the existing sign-stage certificate coverage is not duplicated inconsistently.

### Tests for User Story 3

- [X] T006 [US3] Add contract-alignment cases in `pkg/build/content_digest_test.go` that compare anchor and non-anchor responses for each supported signing identity, verify the exact existing labels and conditions, and verify no digest change occurs from signing enabled/disabled state alone when no applicable stable identity is present

### Implementation for User Story 3

- [X] T007 [US3] Review and finalize the combined anchor input logic in `pkg/build/build_phase.go` so it preserves holistic-input filtering, SBOM behavior, SHA3-224 ordering, and cache lookup semantics while documenting that the `sign` stage already accounts for the manifest signing certificate and chain

**Checkpoint**: All three user stories are independently covered by the focused build-package tests, with no separate signing marker or secret-bearing input.

---

## Phase 6: Polish & Cross-Cutting Concerns

**Purpose**: Run the repository-required quality gates for the two authored implementation files and confirm no unrelated artifacts were changed.

- [X] T008 Run repository formatting with `task format` and verify formatting changes are limited to `pkg/build/build_phase.go` and `pkg/build/content_digest_test.go`
- [X] T009 Run the focused unit suite with `task test:unit paths="./pkg/build/..."` and then the complete unit suite with `task test:unit`, covering `pkg/build/build_phase.go` and `pkg/build/content_digest_test.go`
- [X] T010 Run `task build` and `task deps:install:golangci-lint`, then run `task lint` against the implementation in `pkg/build/build_phase.go` and tests in `pkg/build/content_digest_test.go`
- [ ] T011 Run the required broader validation commands `task test:e2e paths="./test/e2e/build/..." labelFilter="build"` and `task test:integration` for the cache behavior surrounding `pkg/build/build_phase.go`

---

## Dependencies & Execution Order

### Phase Dependencies

- **Setup (Phase 1)**: T001 confirms the existing brownfield locations and has no code dependency.
- **Foundational (Phase 2)**: No tasks; existing infrastructure is already available.
- **User Story 1 (Phase 3)**: T002 should be written first and fail before T003 implements BSign fingerprint support.
- **User Story 2 (Phase 4)**: T004 should follow T003 and fail before T005 implements certificate and chain support.
- **User Story 3 (Phase 5)**: T006 and T007 depend on the combined behavior from T003 and T005.
- **Polish (Phase 6)**: T008-T011 depend on all implementation and test tasks being complete.

### User Story Dependencies

- **User Story 1 (P1)**: Depends only on T001; this is the MVP and has no dependency on other stories.
- **User Story 2 (P1)**: Depends on the existing digest path and follows US1 because both implementation increments modify the same anchor input assembly in `pkg/build/build_phase.go`.
- **User Story 3 (P2)**: Depends on US1 and US2 because alignment tests validate the complete signing input set.

### Within Each User Story

- Write or extend the story-specific tests before its implementation task.
- Preserve the existing private function and option types; do not introduce a public API or helper abstraction.
- Keep all signing inputs conditional and non-secret.
- Complete the story checkpoint with `task test:unit paths="./pkg/build/..."` before proceeding.

### Parallel Opportunities

- No implementation tasks are marked `[P]`: US1, US2, and US3 intentionally touch the same two files and must avoid conflicting edits.
- After the implementation is complete, T009 and T010 can be run independently, although the repository gate order requires formatting before build/lint/tests.
- T011 is an independent broader validation pass after the focused tests and build/lint gates.

---

## Implementation Strategy

### MVP First (User Story 1 Only)

1. Complete T001.
2. Write and run the BSign-focused tests in T002, confirming they fail for the missing fingerprint behavior.
3. Implement T003.
4. Run `task test:unit paths="./pkg/build/..."` and stop at the US1 checkpoint if only BSign cache identity is needed.

### Incremental Delivery

1. Add US1 to invalidate anchors on BSign fingerprint changes.
2. Add US2 to invalidate anchors on in-house certificate and chain changes.
3. Add US3 to enforce anchor/non-anchor contract alignment and document existing sign-stage coverage.
4. Complete T008-T011 before handing off the full feature.

### Final Validation

The final implementation must preserve cache reuse for unchanged applicable inputs, change identity for each changed applicable signing identity, exclude private key material and passphrases, avoid a signing-state-only marker, and leave public APIs, CLI syntax, dependencies, storage formats, and registry protocols unchanged.

---

## Notes

- All tasks use the required checklist format: checkbox, sequential ID, optional `[P]`, required story label in story phases, and an exact file path in the description.
- Tests are included because `spec.md` explicitly requires focused Ginkgo/Gomega coverage.
- No `data-model.md` entities or `contracts/` public endpoints require separate implementation tasks; the internal contract is covered by T006-T007.
