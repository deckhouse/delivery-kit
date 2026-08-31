---

description: "Implementation tasks for systemic anchor digest invalidation"
---

# Tasks: Systemic Anchor Digest Invalidation

**Input**: Design documents from `/specs/020-anchor-digest-invalidation/`

**Prerequisites**: `plan.md`, `spec.md`, `research.md`, `data-model.md`, `contracts/cache-key-contract.md`, and `quickstart.md`

**Tests**: Focused Ginkgo/Gomega unit tests are required by `spec.md` (FR-009 through FR-013). E2E validation is optional follow-up coverage and is not an acceptance gate for this scope.

## Format: `[ID] [P?] [Story] Description`

- **[P]**: Can run in parallel after its stated dependencies are complete
- **[Story]**: User-story traceability label; omitted for setup, foundational, and polish tasks
- Every task includes the concrete file or command path needed to execute it.

## Phase 1: Setup (Repository Context)

**Purpose**: Confirm the existing repository structure and test entry points; no new project initialization is required.

- [X] T001 Verify the existing anchor digest entry point and related `BuildOptions`/`ELFSigningOptions` flow in `pkg/build/build_phase.go` against `specs/020-anchor-digest-invalidation/contracts/cache-key-contract.md`
- [X] T002 [P] Verify the co-located Ginkgo/Gomega unit-test entry points in `pkg/build/build_phase_test.go`, `pkg/build/content_digest_test.go`, and `pkg/build/stage/content_digest_test.go`
- [X] T003 [P] Verify the existing signing and digest-test patterns in `pkg/build/content_digest_test.go`, `pkg/build/stage/content_digest_test.go`, and `test/e2e/build/signature_test.go` for optional follow-up coverage

---

## Phase 2: Foundational (Blocking Prerequisites)

**Purpose**: Establish the implementation and test contract before story-specific work begins.

- [X] T004 Record the ordered anchor cache-key inputs, explicit `BuildCacheVersion` propagation requirement, and absent/disabled/configured signing-state distinctions in `specs/020-anchor-digest-invalidation/contracts/cache-key-contract.md` and `pkg/build/content_digest_test.go`, excluding private keys and passphrases
- [X] T005 [P] Identify the existing stable in-house certificate/chain identity and BSign fingerprint fields available from `pkg/build/signing/` for use by the internal anchor digest path
- [X] T006 [P] Identify the existing non-anchor signing checksum inputs and the `sign` stage checksum coverage in `pkg/build/build_phase.go` before changing the anchor contract

**Checkpoint**: The internal cache-key contract, available non-secret signing identities, and `sign` stage/non-anchor checksum behavior are confirmed; user-story implementation can begin.

---

## Phase 3: User Story 1 - Invalidate Anchors on Build Cache Version Changes (Priority: P1) 🎯 MVP

**Goal**: Include `imagePkg.BuildCacheVersion` in the anchor identity while preserving deterministic reuse for identical complete inputs.

**Independent Test**: Calculate the anchor digest with an explicitly supplied cache version twice unchanged and once with only the version changed; verify determinism, digest invalidation, and explicit-version presence without requiring an end-to-end build.

### Tests for User Story 1

> Write the tests first and confirm they fail against the current anchor early-return behavior before implementing the digest change.

- [X] T007 [P] [US1] Add Ginkgo/Gomega unit coverage that supplies two explicit `BuildCacheVersion` values to `calculateDigest`, verifies deterministic identical-version results, and verifies different-version anchor digests in `pkg/build/content_digest_test.go`
### Implementation for User Story 1

- [X] T008 [US1] Add `BuildCacheVersion string` to the internal `calculateDigestOptions` and populate it explicitly from `imagePkg.BuildCacheVersion` in `BuildPhase.calculateStage` before the `calculateDigest` call in `pkg/build/build_phase.go`
- [X] T009 [US1] Make both anchor and non-anchor `calculateDigest` branches consume the explicitly supplied `opts.BuildCacheVersion`, adding the tagged anchor contribution while preserving the non-anchor digest ordering in `pkg/build/build_phase.go`
- [X] T010 [US1] Run `task test:unit paths="./pkg/build/..." -- -focus='Anchor|Digest'` and verify the explicit version propagation and cache-version assertions in `pkg/build/content_digest_test.go`

**Checkpoint**: User Story 1 independently proves deterministic reuse and rejection of anchors created under a different build cache version.

---

## Phase 4: User Story 2 - Invalidate Anchors on ELF Signing Changes (Priority: P1)

**Goal**: Make anchor identity reflect explicit ELF signing mode and stable non-secret signing identity, including key rotation.

**Independent Test**: Calculate the anchor digest with the same conditional signing components as the non-anchor path, then vary the BSign fingerprint, in-house certificate, or certificate chain; verify unchanged inputs are deterministic and each changed applicable component produces a different identity without requiring a separate enabled/disabled marker.

### Tests for User Story 2

- [ ] T011 [P] [US2] Add Ginkgo/Gomega unit coverage for anchor alignment with non-anchor signing inputs, including BSign fingerprint and in-house certificate/chain changes, and verify no separate enabled/disabled marker is used in `pkg/build/content_digest_test.go`
- [X] T012 [P] [US2] Add unit coverage proving private key bytes and passphrases are not used as anchor digest inputs in `pkg/build/content_digest_test.go`
### Implementation for User Story 2

- [X] T013 [US2] Add the anchor branch's conditional ELF checksum inputs using the same `ELFSigningOptions.Enabled()` conditions, values, and labels as the non-anchor path in `pkg/build/build_phase.go`, without a separate enabled/disabled marker or mode tag
- [X] T014 [US2] Ensure the anchor implementation reuses the existing BSign fingerprint and in-house certificate/chain values without changing signing APIs, CLI flags, or non-anchor signing contributions in `pkg/build/build_phase.go`
- [X] T015 [US2] Add the required concise comment in `calculateDigest` explaining that the `sign` stage already accounts for relevant checksum components, including manifest certificate and chain, so the anchor contract must not duplicate or diverge from them in `pkg/build/build_phase.go`
- [ ] T016 [US2] Run `task test:unit paths="./pkg/build/..." -- -focus='Anchor|Digest|Signing'` and verify signing-component alignment, key-identity, no-marker, and secret-exclusion assertions in `pkg/build/content_digest_test.go`

**Checkpoint**: User Story 2 independently proves signing-state and key-identity changes reject incompatible warmed-cache anchors and preserve compatible signed reuse.

---

## Phase 5: User Story 3 - Preserve Complete Anchor and Non-Anchor Cache Behavior (Priority: P2)

**Goal**: Ensure the anchor fix does not alter the existing non-anchor cache contract and preserves deterministic behavior for unchanged optional inputs.

**Independent Test**: Compare anchor and non-anchor digest inputs while varying cache version, signing inputs, and empty optional holistic inputs; verify non-anchor ordering and existing behavior remain intact.

### Tests for User Story 3

- [X] T017 [P] [US3] Add Ginkgo/Gomega regression coverage for unchanged non-anchor digest sensitivity, explicit cache-version consumption, and input ordering in `pkg/build/content_digest_test.go`
- [X] T018 [P] [US3] Add coverage that empty optional holistic inputs remain normalized consistently on the anchor path in `pkg/build/content_digest_test.go`


### Implementation for User Story 3

- [X] T019 [US3] Compare the final anchor and non-anchor `calculateDigest` input sequences in `pkg/build/build_phase.go` and preserve all existing non-anchor contributions while ensuring the explicit cache-version value replaces the previous hidden global read
- [X] T020 [US3] Verify that the `sign` stage's existing checksum inputs are not duplicated or contradicted by the anchor contribution in `pkg/build/build_phase.go`

**Checkpoint**: User Story 3 independently demonstrates that cache-version/signing changes are represented consistently and existing non-anchor behavior remains intact.

---

## Phase 6: Polish & Cross-Cutting Concerns

**Purpose**: Validate the required unit-scope implementation and preserve the repository's API, security, and style constraints.

- [X] T021 [P] Run `task format` and inspect authored-file changes for unintended formatting or generated-file modifications
- [X] T022 Run `task build` and resolve only feature-scope compilation failures in `pkg/build/build_phase.go` and `pkg/build/content_digest_test.go`
- [X] T023 Run `task deps:install:golangci-lint` once for the session, then run `task lint` and address feature-scope diagnostics
- [ ] T024 Run `task test:unit` after focused tests pass and verify no unrelated package failures were introduced
- [X] T025 [P] Review `pkg/build/build_phase.go` and `pkg/build/content_digest_test.go` for secret exclusion, explicit cache-version propagation, the required `sign` stage comment, unchanged public API/CLI behavior, and absence of unnecessary dependencies
- [ ] T026 [P] Optionally run `task test:e2e paths="./test/e2e/build/..." labelFilter="anchor-digest"` using existing fixtures to validate warmed-cache behavior without treating E2E failure or registry availability as a blocker

---

## Dependencies & Execution Order

### Phase Dependencies

- **Setup (Phase 1)**: No implementation dependencies; confirms repository entry points.
- **Foundational (Phase 2)**: Depends on Setup; blocks user-story implementation.
- **User Stories (Phases 3–5)**: Depend on Foundational. US1 and US2 touch the same digest implementation and should normally be delivered sequentially; US3 verifies the combined result.
- **Polish (Phase 6)**: Depends on all required story work; required validation commands run in the listed order. Optional E2E follow-up may run independently after implementation.

### User Story Dependencies

- **User Story 1 (P1)**: Can start after Phase 2; MVP and primary owner of the anchor cache-version implementation.
- **User Story 2 (P1)**: Can start after Phase 2, but its implementation integrates with the explicit propagation and anchor branch changed by US1; run after T010 to avoid conflicting edits.
- **User Story 3 (P2)**: Depends on the completed explicit propagation, aligned signing implementation, and `sign` stage documentation from US1/US2 so it can verify the final path against the unchanged non-anchor contract.

### Parallel Opportunities

- T002, T003, T005, and T006 can run in parallel after setup.
- T007 can be prepared before T009; T009 and T010 are sequential because T010 consumes the new internal option.
- T011 and T012 can be prepared in parallel before T013.
- T017 and T018 can be prepared in parallel; T020 depends on the completed signing implementation.
- T021 and T025 can run in parallel after implementation; T026 is optional follow-up. The remaining required polish gates are intentionally ordered.

### Parallel Example: User Story 1

```text
Task: T007 — add explicit-version/determinism unit tests in pkg/build/content_digest_test.go
```

### Parallel Example: User Story 2

```text
Task: T011 — add signing-state transition unit tests in pkg/build/content_digest_test.go
Task: T012 — add secret-exclusion unit coverage in pkg/build/content_digest_test.go
```

---

## Implementation Strategy

### MVP First (User Story 1 Only)

1. Complete Phase 1 and Phase 2.
2. Add failing unit tests for explicit cache-version sensitivity.
3. Add and populate the internal `BuildCacheVersion` option, then update the anchor branch in `pkg/build/build_phase.go`.
4. Run the focused unit checks.
5. Stop for an independently demonstrable MVP before adding signing-state coverage.

### Incremental Delivery

1. Deliver US1: explicit cache-version propagation and anchor invalidation.
2. Deliver US2: aligned ELF signing identity inputs and signing-state tests.
3. Deliver US3: non-anchor regression coverage and verification of the `sign` stage contract documentation.
4. Complete Phase 6 required repository gates; run optional E2E follow-up when useful.

## Notes

- Every task is a checklist item with a sequential ID; story tasks carry exactly one `[USn]` label.
- `[P]` is used only where work can be performed independently without an incomplete-file dependency.
- No new public API, CLI syntax, dependency, persistence schema, or secret-bearing cache input is planned.
- Cryptographic signature verification and warmed-cache E2E validation are outside the required acceptance scope; optional E2E tests may assert cache identity and build behavior.
