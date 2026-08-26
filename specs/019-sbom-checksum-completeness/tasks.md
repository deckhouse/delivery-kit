# Tasks: SBOM Checksum Completeness

**Input**: Design documents from `/specs/019-sbom-checksum-completeness/`
**Prerequisites**: plan.md, spec.md, research.md, data-model.md, contracts/checksum.md, quickstart.md

**Organization**: Tasks grouped by user story. Both stories modify the same function, so US2 builds on the US1 change, but each remains independently verifiable through its own tests.

## Phase 1: Setup

- [X] T001 Verify branch `fix/sbom/checksum-completeness` is current and clean; run `task deps:install:golangci-lint` (once per session)

## Phase 2: Foundational

- [X] T002 Read `pkg/build/sbom_step.go` (`calculateStableChecksum`, `ConvergeWithMerge`) and the existing checksum tests in `pkg/build/sbom_step_checksum_test.go` to anchor the exact current part layout before changing it

## Phase 3: User Story 1 — Changing GOST configuration regenerates the SBOM (P1)

**Note**: The original US1 (os-pm toggle) was dropped during implementation: the os-pm directive feeds the Packages stage digest through its generated install command (the stage appears/disappears with the directive), so any toggle changes the parent digest and misses the SBOM cache without the checksum's help. os-pm is documented as an intentional exclusion instead.

- [X] T003 [US1] Rework `calculateStableChecksum` in `pkg/build/sbom_step.go`: encode all parts as fixed-arity keyed arguments to `util.Sha256Hash(parts...)` (layout per data-model.md §Inputs); add the contract doc comment listing intentional exclusions incl. scratch mode and the os-pm directive (FR-006)
- [X] T004 [P] [US1] Consolidated checksum tests in `pkg/build/sbom_step_checksum_test.go`: Ginkgo `DescribeTable` with baseline stability and single-input flips; run `task test:unit paths="./pkg/build/..."`
- [X] T005 [P] [US1] E2E GOST-toggle scenario `test/e2e/sbom/gost_cache_invalidation_test.go` + fixtures `_fixtures/gost_toggle/state0|state1`: scratch image, only GOST config changes between states → no stage rebuild marker, SBOM regeneration marker, updated GOST properties in the SBOM; unchanged rebuild asserts cache reuse. Written and compiled; run blocked locally (no WERF_TEST_K8S_DOCKER_REGISTRY, macOS) — must run in CI

**Checkpoint**: US1 fully functional — GOST changes invalidate the SBOM cache.

## Phase 4: GOST checksum channel (implementation detail of US1)

**Goal**: GOST config is an explicit checksum channel, effective even with empty merge opts.

**Verification**: Unit — changing `AttackSurface` or `SecurityFunction` changes the checksum with and without base/import BOMs.

- [X] T006 [US1] In `pkg/build/sbom_step.go` add `gost_attack_surface` / `gost_security_function` keyed parts from `mergeOpts.Gost` to `calculateStableChecksum` (single explicit channel per FR-002; `MergeOpts.Checksum()` in `pkg/sbom/cyclonedxutil/merge.go` stays untouched)
- [X] T007 [US1] Checksum table covers: each GOST field change flips the checksum with empty `MergeOpts`; run `task test:unit paths="./pkg/build/..."`

## Phase 5: User Story 2 — Distinct settings never share a checksum (P2)

**Goal**: Injective part encoding; no empty-part collisions or positional shifting.

**Independent Test**: Unit — collision-focused table cases pass.

- [X] T008 [US2] Collision cases in `pkg/build/sbom_step_checksum_test.go`: separator-absorbing values (`signer="a-b"`+empty platform vs `signer="a"`+`platform="b"` — the case that actually falsifies the old join encoding, found via mutation testing); same value moving between adjacent parts; pairwise-distinct checksums across single-input flips

**Checkpoint**: All user stories independently verified.

## Phase 6: Polish & Verification

- [X] T009 Applied `.agents/skills/test-the-tests/SKILL.md`: 3 mutations (drop GOST parts, drop a part, revert to join encoding); mutation 3 exposed a vacuous collision test which was strengthened until it falsifies
- [X] T010 Gates run locally per quickstart.md: `task format`, `task build`, `task lint`, `task test:unit` — all green (`pkg/build` scoped and full; the full run surfaces pre-existing flakes in unrelated suites that pass in isolation)
- [ ] T011 Run `task test:e2e paths="./test/e2e/sbom/..." labelFilter="sbom"` and `task test:integration` in CI — blocked locally (no `WERF_TEST_K8S_DOCKER_REGISTRY`, macOS host). Merge is gated on these being green

## Dependencies

- T001 → T002 → T003 → (T004, T005 [P] after T003) → T006 → T007 → T008 → T009 → T010 → T011 (CI)

## Implementation Strategy

- Single PR, single invalidation wave (FR-005). E2E and integration runs happen in CI (local env lacks the e2e registry).
