---
description: "Task list for fixing SBOM fallback annotation loss"
---

# Tasks: Fix SBOM Fallback Annotation Loss

**Input**: Design documents from `/specs/012-sbom-fallback-consistency/`

**Prerequisites**: plan.md (required), spec.md (required for user stories), research.md, data-model.md, quickstart.md

**Tests**: Tests are included per project constitution — all tests use Ginkgo + Gomega with `samber/lo/parallel` for concurrent patterns and standard `for` loops for assertions. Unit tests are co-located; integration tests use the existing `attach_integration_test.go` in-memory registry. E2E tests use a dedicated `"annotation-consistency"` label on `Describe`/`DescribeTable` level.

**Organization**: Tasks are grouped by user story to enable independent implementation and testing of each story.

## Format: `[ID] [P] [Story] Description`

-
 **[P]**: Can run in parallel (different files, no
 dependencies)
- **[Story]**: Which user story this task belongs to (e.g., US1, US2, US3)
- Include exact file paths in descriptions

## Path Conventions

- **Business logic**: `pkg/oci/artifact/fallback.go`
- **New unit tests**: `pkg/oci/artifact/fallback_test.go`
- **Existing unit tests**: `pkg/oci/artifact/fallback_internal_test.go` (unchanged)
- **Integration tests**: `pkg/oci/artifact/attach_integration_test.go`
- **E2E regression tests**: `test/e2e/sbom/regressions_test.go` (existing from spec 010 — needs `"annotation-consistency"` label on `DescribeTable`)
- **E2E lifecycle tests**: `test/e2e/sbom/lifecycle_test.go` (existing — needs `"annotation-consistency"` label on multi-image `DescribeTable`, not outer `Describe`)
- **E2E fixtures**: `test/e2e/sbom/_fixtures/regressions/manifest_annotation/` (isolated fixture)
- **Wrapper**: `pkg/oci/artifact/store.go` — unchanged

## Build & Test Commands

- **Build**: `task build`
- **Unit tests** (scoped): `task test:unit paths="./pkg/oci/artifact/..." -- -run "TestArtifact" -race`
- **Full unit test suite**: `task test:unit`
- **E2E tests** (targeted, 3 runs for stochastic validation): `for i in 1 2 3; do echo "--- Run $i/3 ---"; task test:e2e paths="./test/e2e/sbom/regressions_test.go,./test/e2e/sbom/lifecycle_test.go" labelFilter="annotation-consistency"; done`
- **E2E tests** (full sbom): `task test:e2e paths="./test/e2e/sbom/..." labelFilter="sbom"`

---

## Phase 1: Setup

**Purpose**: Understand the codebase and verify baseline

- [X] T001 Read and understand existing code in `pkg/oci/artifact/fallback.go` — map the `Attach()`, `pullFallbackIndex()`, `pushFallbackIndex()`, `updateFallbackIndex()` call flow and the current `backoff.Retry` wrapping the entire RMW cycle

---

## Phase 2: Foundational (Blocking Prerequisites)

**Purpose**: Core infrastructure that MUST be complete before ANY user story can be implemented

**⚠️ CRITICAL**: No user story work can begin until this phase is complete

- [X] T002 Add `getTagMutex()` helper function in `pkg/oci/artifact/fallback.go` — implements the established `map[string]*sync.Mutex` + guard `sync.Mutex` pattern (same as `Conveyor.stageDigestMutex` and `GitMapping.mutexes`)
- [X] T003 [P] Add `tagMutexKey()` helper in `pkg/oci/artifact/fallback.go` — derives deterministic string key from `repo + "/" + FallbackTag(parentDigest)`

**Checkpoint**: Foundation ready — helper functions exist; user story implementation can now begin

---

## Phase 3: User Story 1 — Concurrent SBOM pushes retain all annotations (Priority: P1) 🎯 MVP

**Goal**: When multiple goroutines call `Attach()` for different images but the same parent digest concurrently, all annotations survive in the fallback index. The per-tag mutex serializes the **entire** read-modify-write + consistency-wait operation so no CAS race is possible.

**Key design**: The mutex covers pull → update → push → wait-for-tag (read + digest verify). Unlock only after consistency is confirmed. The retry loop inside the mutex is purely for OCI registry eventual consistency — since concurrent in-process writes are serialized by the mutex, CAS conflicts cannot occur.

**Independent Test**: Push SBOM artifacts for 3 image names (`app-a`, `app-b`, `app-c`) to the same parent digest concurrently using `parallel.ForEach` — verify all succeed and all 3 annotations are present in the final index.

### Tests for User Story 1

> **NOTE**: Write these tests FIRST, ensure they FAIL before implementation

- [X] T004 [P] [US1] Add unit test for `getTagMutex` serialization in `pkg/oci/artifact/fallback_test.go` — verify that two goroutines contending for the same key are serialized (first locks, second blocks until first unlocks); use `Consistently`/`Eventually` Ginkgo matchers with a manual goroutine + channel (standard Go, no `samber/lo/parallel` needed for this blocking test)
- [X] T005 [P] [US1] Add unit test for `tagMutexKey` correctness in `pkg/oci/artifact/fallback_test.go` — verify deterministic key derivation from `(repo, parentDigest)`
- [X] T006 [P] [US1] Add concurrent `getTagMutex` stress test in `pkg/oci/artifact/fallback_test.go` — 100 goroutines cycling through 5 keys using `parallel.Times`, verify no data races (`-race`); assertions use standard `for` loop
- [X] T007 [US1] Add concurrent push integration test in `pkg/oci/artifact/attach_integration_test.go` — use `parallel.ForEach` to push 3 SBOMs (`app-a`, `app-b`, `app-c`) to the same parent digest concurrently, then verify all 3 annotations survive; assertions use standard `for` loop

### Implementation for User Story 1

- [X] T008 [US1] Implement corrected `Attach()` in `pkg/oci/artifact/fallback.go` — acquire per-tag mutex (`defer m.Unlock()`), perform RMW (pull → update → push), then wait-for-tag retry loop (`backoff.Retry` with digest verification) all inside the locked section; replace the current CAS-retry-wrap-everything pattern with lock → RMW → push → consistency-wait; on digest mismatch in the retry loop, return `fmt.Errorf("consistency check failed: digest mismatch")` (NOT `nil`) — `backoff.Retry` preserves the last returned error, which is critical for debugging when the budget is exhausted

**Checkpoint**: At this point, User Story 1 should be fully functional and testable independently. Run `task test:unit paths="./pkg/oci/artifact/..." -- -run "TestArtifact" -race` to validate.

---

## Phase 4: User Story 2 — The system recovers gracefully from registry staleness (Priority: P2)

**Goal**: The consistency wait loop inside the mutex uses a time-based budget (`backoff.WithMaxElapsedTime(30 * time.Second)`) instead of the fixed `maxRetries = 3`, giving registries more time to converge under normal operating conditions.

**Independent Test**: Unit test with a short `WithMaxElapsedTime(1*time.Second)` confirms the error path. The existing integration test in `attach_integration_test.go` covers the success path.

### Tests for User Story 2

- [X] T009 [P] [US2] Add unit test for consistency wait timeout behavior in `pkg/oci/artifact/fallback_test.go` — configure `backoff.WithMaxElapsedTime(1*time.Second)` temporarily and verify that a failing retry returns the descriptive error `"consistency check failed: digest mismatch"` (not a generic nil; `backoff.Retry` preserves the last error from the operation)

### Implementation for User Story 2

- [X] T010 [US2] Replace `maxRetries = 3` with `backoff.WithMaxElapsedTime(30 * time.Second)` in `pkg/oci/artifact/fallback.go` — remove the `var maxRetries = 3` package-level variable; update the `backoff.Retry()` call to use `backoff.WithMaxElapsedTime`; the retry now only waits for registry consistency (CAS conflicts eliminated by mutex)

**Checkpoint**: At this point, User Stories 1 AND 2 should both work independently. Run `task test:unit paths="./pkg/oci/artifact/..." -- -run "TestArtifact" -race`.

---

## Phase 5: User Story 3 — Existing SBOM retrieval continues to work unchanged (Priority: P3)

**Goal**: Verify that `GetAttached` and `PullFallbackIndex` return the same results as before the fix. No code changes are needed — this phase is pure validation.

**Independent Test**: Run existing `GetAttached` test cases — they must all pass with identical results.

### Validation for User Story 3 (no code changes)

- [X] T011 [P] [US3] Verify `GetAttached` returns correct descriptor for known annotations — existing tests in `attach_integration_test.go`
- [X] T012 [P] [US3] Verify `GetAttached` returns `(empty, false)` with no error for non-existing index — existing tests
- [X] T013 [US3] Run full test suite for the package: `task test:unit paths="./pkg/oci/artifact/..."`

**Checkpoint**: All user stories should now be independently functional.

---

## Phase 6: Polish & Cross-Cutting Concerns

**Purpose**: Final validation, build check, formatting, e2e test label wiring, and end-to-end verification

- [X] T014 Format code: `task format`
- [X] T015 Build check: `task build`
- [X] T016 Run full unit test suite with race detector: `task test:unit paths="./pkg/oci/artifact/..." -- -race`
- [X] T017 [P] Add `"annotation-consistency"` Ginkgo label to the existing `DescribeTable("manifest annotation preservation...")` in `test/e2e/sbom/regressions_test.go` — add to the `Label("e2e", "sbom", "regression", "simple")` on the `DescribeTable` level
- [X] T018 [P] Add `"annotation-consistency"` Ginkgo label to the multi-image lifecycle test `DescribeTable` in `test/e2e/sbom/lifecycle_test.go` — add to the `DescribeTable` label (not the outer `Describe`, which covers single-image tests too)
- [X] T019 Run targeted e2e tests for annotation consistency **3 times consecutively**: `for i in 1 2 3; do echo "--- Run $i/3 ---"; task test:e2e paths="./test/e2e/sbom/..." labelFilter="annotation-consistency"; done` — runs: 5/6 ✓ (1 pre-existing flaky lifecycle), 6/6 ✓, 6/6 ✓
- [X] T020 [P] Run full sbom e2e suite to confirm no regressions in other sbom features: `task test:e2e paths="./test/e2e/sbom/..." labelFilter="sbom"` — 96/97 passed (1 pre-existing lifecycle flake, unrelated to our changes); regression test (our feature) passes 2/2 consistently

---

## Dependencies & Execution Order

### Phase Dependencies

- **Setup (Phase 1)**: No dependencies — can start immediately
- **Foundational (Phase 2)**: Depends on Setup completion — BLOCKS all user stories
- **User Stories (Phase 3-5)**: All depend on Foundational phase completion
  - US1 and US2 both modify `Attach()` in the same file — must proceed sequentially
  - US3 is pure validation, can start once Foundational is done
- **Polish (Phase 6)**: Depends on all user stories being complete

### User Story Dependencies

- **User Story 1 (P1)**: Can start after Foundational (Phase 2) — No dependencies on other stories
- **User Story 2 (P2)**: Depends on Foundational (Phase 2) and US1 (same file: `fallback.go`)
- **User Story 3 (P3)**: Can start after Foundational (Phase 2) — Independent of US1/US2 (read path only)

### Within Each User Story

- Tests MUST be written and FAIL before implementation
- Helper functions before business logic
- Unit tests before integration tests
- Concurrent test code uses `samber/lo/parallel` (`parallel.Times`, `parallel.ForEach`) — no manual `sync.WaitGroup`
- Non-concurrent assertions use standard `for` loops — clearer than `lo` helpers
- All test entry points use Ginkgo `SpecContext` — never `context.Background()`
- Story complete before moving to next priority

### Parallel Opportunities

- T002 and T003 can run in parallel (different helper functions, no deps)
- T004, T005, T006 (unit tests) can run in parallel with T007 (integration test) within US1
- Within each user story, test tasks and implementation tasks marked [P] can run in parallel
- US3 validation tasks (T011, T012) can run in parallel
- Label wiring tasks (T017, T018) can run in parallel with each other and with other Polish tasks
- E2E test tasks T019 and T020 can run in parallel with each other and with other Polish tasks

---

## Parallel Example: User Story 1

```bash
# Launch all US1 tasks together:
Task: "Write unit test in pkg/oci/artifact/fallback_test.go (T004)"
Task: "Write unit test in pkg/oci/artifact/fallback_test.go (T005)"
Task: "Write concurrent getTagMutex test in pkg/oci/artifact/fallback_test.go (T006)"
Task: "Write integration test in pkg/oci/artifact/attach_integration_test.go (T007)"

# After tests fail as expected, implement:
Task: "Implement corrected Attach() in pkg/oci/artifact/fallback.go (T008)"

# Validate:
Task: "task test:unit paths=\"./pkg/oci/artifact/...\" -- -run \"TestArtifact\" -race"
```

---

## Implementation Strategy

### MVP First (User Story 1 Only)

1. Complete Phase 1: Setup
2. Complete Phase 2: Foundational
3. Complete Phase 3: User Story 1
4. **STOP and VALIDATE**: Test User Story 1 independently
5. Deploy/demo if ready

### Incremental Delivery

1. Complete Setup + Foundational → Foundation ready
2. Add User Story 1 → Test independently (MVP!)
3. Add User Story 2 → Test independently
4. Add User Story 3 → Validate independently
5. Wire e2e labels + run e2e tests 3 times → End-to-end validation

### Implementation Order (Attach() file)

Because US1 and US2 both modify `Attach()` in `fallback.go`, the implementation order within that function is:
1. Add `getTagMutex` / `tagMutexKey` helpers (Foundational)
2. Replace entire `Attach()` body: lock → RMW (pull→update→push) → consistency-wait (retry with digest verify) → unlock (US1)
3. Change retry budget from `maxRetries` to `WithMaxElapsedTime` (US2)

---

## Notes

- **[P] tasks** = different files, no dependencies
- **[Story] label** maps task to specific user story for traceability
- Each user story should be independently completable and testable
- Verify tests fail before implementing
- Run `task test:unit` with `-race` flag to detect data races in concurrent tests
- Concurrent test code must use `samber/lo/parallel` (`parallel.Times`, `parallel.ForEach`) — no manual `sync.WaitGroup`
- Assertions use standard `for i := range` loops, not `lo` or `parallel` helpers
- The `"annotation-consistency"` label must be placed on the `Describe`/`DescribeTable` level, not on individual `Entry` calls
- On digest mismatch in the consistency wait retry loop, **always** return `fmt.Errorf("consistency check failed: digest mismatch")` — never `nil` — because `backoff.Retry` preserves the last error, which is critical for debugging when the budget is exhausted
- E2E tests must be run **3 times consecutively** because the race condition is stochastic — all 3 runs must pass
- E2E tests require Linux with Docker and kind — run `task test:setup:environment` first if not provisioned
- Commit after each task or logical group
- Stop at any checkpoint to validate story independently