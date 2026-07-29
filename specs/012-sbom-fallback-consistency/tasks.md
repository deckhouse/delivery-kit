---
description: "Task list for fixing SBOM fallback annotation loss"
---

# Tasks: Fix SBOM Fallback Annotation Loss

**Input**: Design documents from `/specs/012-sbom-fallback-consistency/`

**Prerequisites**: plan.md (required), spec.md (required for user stories), research.md, data-model.md

**Tests**: Tests are included per project constitution — all tests use Ginkgo + Gomega. Unit tests are co-located; integration tests use the existing `attach_integration_test.go` in-memory registry. E2E regression tests (from spec 010) use an isolated fixture with no shared state.

**Organization**: Tasks are grouped by user story to enable independent implementation and testing of each story.

## Format: `[ID] [P] [Story] Description`

- **[P]**: Can run in parallel (different files, no dependencies)
- **[Story]**: Which user story this task belongs to (e.g., US1, US2, US3)
- Include exact file paths in descriptions

## Path Conventions

- **Business logic**: `pkg/oci/artifact/fallback.go`
- **New unit tests**: `pkg/oci/artifact/fallback_test.go`
- **Existing unit tests**: `pkg/oci/artifact/fallback_internal_test.go` (unchanged)
- **Integration tests**: `pkg/oci/artifact/attach_integration_test.go`
- **E2E regression tests**: `test/e2e/sbom/regressions_test.go` (existing from spec 010)
- **E2E fixtures**: `test/e2e/sbom/_fixtures/regressions/manifest_annotation/` (isolated, shared with no other suite)

## Build & Test Commands

- **Build**: `task build`
- **Unit tests** (scoped): `task test:unit paths="./pkg/oci/artifact/..." -- -run "TestArtifact" -race`
- **Full unit test suite**: `task test:unit paths="./pkg/oci/artifact/..."`
- **E2E tests** (scoped by label): `task test:e2e paths="./test/e2e/sbom/..." labelFilter="regression"`
- **E2E tests** (full sbom suite): `task test:e2e paths="./test/e2e/sbom/..." labelFilter="sbom"`

---

## Phase 1: Setup

**Purpose**: Understand the codebase and verify baseline

- [X] T001 Read and understand existing code in `pkg/oci/artifact/fallback.go` — map the `Attach()`, `pullFallbackIndex()`, `pushFallbackIndex()`, `updateFallbackIndex()` call flow and CAS retry loop

---

## Phase 2: Foundational (Blocking Prerequisites)

**Purpose**: Core infrastructure that MUST be complete before ANY user story can be implemented

**⚠️ CRITICAL**: No user story work can begin until this phase is complete

- [X] T002 Add `getTagMutex()` helper function in `pkg/oci/artifact/fallback.go` — implements the established `map[string]*sync.Mutex` + guard `sync.Mutex` pattern (same as `Conveyor.stageDigestMutex` and `GitMapping.mutexes`)
- [X] T003 [P] Add `tagMutexKey()` helper in `pkg/oci/artifact/fallback.go` — derives deterministic string key from `repo + "/" + FallbackTag(parentDigest)`

**Checkpoint**: Foundation ready — helper functions exist; user story implementation can now begin

---

## Phase 3: User Story 1 — Concurrent SBOM pushes retain all annotations (Priority: P1) 🎯 MVP

**Goal**: When multiple goroutines call `Attach()` for different images but the same parent digest concurrently, all annotations survive in the fallback index. The per-tag mutex serializes writes before entering the CAS loop.

**Independent Test**: Push SBOM artifacts for 3 image names (`app-a`, `app-b`, `app-c`) to the same parent digest concurrently via `sync.WaitGroup` goroutines — verify all succeed and all 3 annotations are present in the final index.

### Tests for User Story 1

> **NOTE**: Write these tests FIRST, ensure they FAIL before implementation

- [X] T004 [P] [US1] Add unit test for `getTagMutex` serialization in `pkg/oci/artifact/fallback_test.go` — verify that two goroutines contending for the same key are serialized (concurrent access to same key blocks)
- [X] T005 [P] [US1] Add unit test for `tagMutexKey` correctness in `pkg/oci/artifact/fallback_test.go` — verify deterministic key derivation
- [X] T006 [US1] Add concurrent push integration test in `pkg/oci/artifact/attach_integration_test.go` — use `sync.WaitGroup` to push 3 SBOMs (`app-a`, `app-b`, `app-c`) to the same parent digest concurrently, then verify all 3 annotations survive

### Implementation for User Story 1

- [X] T007 [US1] Integrate `getTagMutex` into `Attach()` in `pkg/oci/artifact/fallback.go` — acquire per-tag mutex (defer unlock) before entering the CAS retry loop, keyed by `tagMutexKey(repo, parentDigest)`

**Checkpoint**: At this point, User Story 1 should be fully functional and testable independently. Run `task test:unit paths="./pkg/oci/artifact/..." -- -run "TestArtifact" -race` to validate.

---

## Phase 4: User Story 2 — The system recovers gracefully from registry staleness (Priority: P2)

**Goal**: Replace the fixed `maxRetries = 3` budget with `backoff.WithMaxElapsedTime(30 * time.Second)` so the system retries longer when the registry returns stale data after a write.

**Independent Test**: After a successful push to the fallback index, the read-after-write digest verification succeeds (the existing test in `fallback_internal_test.go` covers basic digest verification). For timeout behavior, a unit test using a short `WithMaxElapsedTime` confirms the error path.

### Tests for User Story 2

- [X] T008 [P] [US2] Add unit test for retry timeout behavior in `pkg/oci/artifact/fallback_test.go` — configure `backoff.WithMaxElapsedTime(1*time.Second)` temporarily and verify that a failing retry returns an error

### Implementation for User Story 2

- [X] T009 [US2] Replace `maxRetries = 3` with `backoff.WithMaxElapsedTime(30 * time.Second)` in `pkg/oci/artifact/fallback.go` — remove the `var maxRetries = 3` package-level variable; update the `backoff.Retry()` call to use `backoff.WithMaxElapsedTime`

**Checkpoint**: At this point, User Stories 1 AND 2 should both work independently. Run `task test:unit paths="./pkg/oci/artifact/..." -- -run "TestArtifact" -race`.

---

## Phase 5: User Story 3 — Existing SBOM retrieval continues to work unchanged (Priority: P3)

**Goal**: Verify that `GetAttached` and `PullFallbackIndex` return the same results as before the fix. No code changes are needed — this phase is pure validation.

**Independent Test**: Run existing `GetAttached` test cases — they must all pass with identical results.

### Validation for User Story 3 (no code changes)

- [X] T010 [P] [US3] Verify `GetAttached` returns correct descriptor for known annotations — existing tests in `attach_integration_test.go`
- [X] T011 [P] [US3] Verify `GetAttached` returns `(empty, false)` with no error for non-existing index — existing tests
- [X] T012 [US3] Run full test suite for the package: `task test:unit paths="./pkg/oci/artifact/..."`

**Checkpoint**: All user stories should now be independently functional.

---

## Phase 6: Polish & Cross-Cutting Concerns

**Purpose**: Final validation, build check, formatting, and end-to-end verification

- [X] T013 Format code: `task format`
- [X] T014 Build check: `task build`
- [X] T015 Run full unit test suite with race detector: `task test:unit paths="./pkg/oci/artifact/..." -- -race`
- [ ] T016 [P] Run existing e2e regression test for manifest annotation preservation: `task test:e2e paths="./test/e2e/sbom/..." labelFilter="regression"` — verifies fallback index annotations survive end-to-end using the isolated fixture at `test/e2e/sbom/_fixtures/regressions/manifest_annotation/` (existing from spec 010)
- [ ] T017 [P] Run full sbom e2e suite to confirm no regressions in other sbom features: `task test:e2e paths="./test/e2e/sbom/..." labelFilter="sbom"`