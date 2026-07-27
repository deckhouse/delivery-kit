# Tasks: Reduce PURL Resolver Retries Duration

**Input**: Design documents from `specs/011-reduce-purl-retries-duration/`

**Prerequisites**: plan.md, spec.md (required), research.md, data-model.md, contracts/README.md

**Tests**: Test tasks are included per the implementation plan.

**Organization**: Tasks are grouped by user story to enable independent implementation and testing of each story.

## Format: `[ID] [P?] [Story] Description`

- **[P]**: Can run in parallel (different files, no dependencies)
- **[Story]**: Which user story this task belongs to (e.g., US1, US2)
- Include exact file paths in descriptions

## Path Conventions

- **CLI commands**: `cmd/werf/<domain>/`
- **Business logic**: `pkg/<domain>/`
- **Unit tests**: co-located with source files as `*_test.go`
- **AI-written tests**: `*_ai_test.go` with `TestAI_` prefix
- **E2E tests**: `test/e2e/<domain>/`
- **Test helpers**: `test/pkg/`

## Build & Test Commands

- **Build**: `task build` (produces `./bin/werf`)
- **Unit tests**: `task test:unit -- -run Test.*externalref ./pkg/sbom/externalref/...`
- **Linting**: `task lint:golangci-lint -- golangciPaths="./pkg/..."` (do NOT run raw `golangci-lint`)
- **Formatting**: `task format`

---

## Phase 1: Setup (Shared Infrastructure)

**Purpose**: Verify project and tooling are ready

- [X] T001 Verify working directory and tooling (check `go.mod`, `Taskfile.yml`, `task build` works)

---

## Phase 2: Foundational (Blocking Prerequisites)

**Purpose**: Understand the current retry configuration before making changes

**⚠️ CRITICAL**: No user story work can begin until this phase is complete

- [X] T002 [P] Read and understand current retry configuration in `pkg/sbom/externalref/service.go` — confirm `MaxElapsedTime` (line 59) and default `timeout` (line 35) values

**Checkpoint**: Foundation ready — user story implementation can now begin

---

## Phase 3: User Story 1 — Reduce PURL Resolution Wait Time (Priority: P1) 🎯 MVP

**Goal**: Reduce the PURL resolution retry window from 30 s to 10 s and lower the HTTP client timeout from 30 s to 5 s, so that a single hung request does not exhaust the entire retry budget.

**Independent Test**: Set up a mock PURL resolution server returning 429/5xx and verify that resolution fails within the target 10 s (not 30 s).

### Tests for User Story 1 ⚠️

> **NOTE**: Write these tests FIRST, ensure they FAIL before implementation (using the old values), then implement the change and verify they PASS.

- [X] T003 [P] [US1] Add test verifying default HTTP timeout is 5 s in `pkg/sbom/externalref/service_test.go`
- [X] T004 [P] [US1] Add test verifying `MaxElapsedTime` is 10 s (document the constant in a testable form) in `pkg/sbom/externalref/service_test.go`

### Implementation for User Story 1

- [X] T005 [P] [US1] Reduce `MaxElapsedTime` from 30 s to 10 s in `pkg/sbom/externalref/service.go` line 59 (`backoff.WithMaxElapsedTime(10*time.Second)`)
- [X] T006 [P] [US1] Reduce default HTTP timeout from 30 s to 5 s in `pkg/sbom/externalref/service.go` line 35 (`timeout = 5*time.Second`)
- [X] T007 [US1] Run unit tests to verify all existing tests pass with the new timing values: `task test:unit -- -run Test.*externalref ./pkg/sbom/externalref/...`

**Checkpoint**: At this point, User Story 1 should be fully functional — PURL resolution retries complete within 10 s instead of 30 s, with a 5 s HTTP request timeout.

---

## Phase 4: User Story 2 — Predictable Failure in CI/CD (Priority: P2)

**Goal**: Ensure that the faster retry exhaustion produces clear, actionable error messages and that existing error aggregation and warning logging behavior is preserved.

**Independent Test**: Configure the resolution service to be completely unreachable and verify the enrichment operation reports an error within the target 10 s per PURL with clear warning messages.

### Implementation for User Story 2

- [X] T008 [US2] Verify that warning messages during retries (in `pkg/sbom/externalref/service.go` `backoff.WithNotify` callback) are preserved — no changes needed, just confirm the logger call is intact
- [X] T009 [US2] Verify that failed resolutions are still aggregated as errors by the enricher (`pkg/sbom/externalref/enricher.go`) — no changes needed, just confirm error aggregation is preserved
- [X] T010 [US2] Run full `externalref` test suite to verify no regressions: `task test:unit ./pkg/sbom/externalref/...`

**Checkpoint**: CI/CD pipelines now fail faster with clear error messages when PURL resolution is unavailable.

---

## Phase 5: Polish & Cross-Cutting Concerns

**Purpose**: Build verification, linting, and final validation

- [ ] T011 [P] Run `task build` to verify the project builds cleanly
- [ ] T012 Run `task lint:golangci-lint -- golangciPaths="./pkg/sbom/externalref/..."` to verify no linting regressions
- [ ] T013 [P] Run `task format` to ensure code formatting is consistent

---

## Dependencies & Execution Order

### Phase Dependencies

- **Setup (Phase 1)**: No dependencies — can start immediately
- **Foundational (Phase 2)**: Depends on Setup completion — BLOCKS all user stories
- **User Stories (Phase 3–4)**: All depend on Foundational phase completion
  - US1 (Phase 3) must be completed before US2 (Phase 4), since US2 verifies behavior that depends on the US1 configuration change
- **Polish (Phase 5)**: Depends on all user stories being complete

### User Story Dependencies

- **User Story 1 (P1)**: Core retry budget and timeout change — no dependencies on other stories
- **User Story 2 (P2)**: Verification of logging and error aggregation — depends on US1 being complete

### Within Each User Story

- Tests MUST be written and FAIL before implementation
- Core constants before verification
- Implementation complete before running full test suite

### Parallel Opportunities

- T002 and T003 can run in parallel (different files, no dependencies)
- T005 and T006 can run in parallel (same file, but different lines — no conflict)
- T008, T009, T010 can run sequentially (verification tasks)
- T011, T012, T013 run in parallel in Polish phase

---

## Parallel Example: User Story 1

```bash
# Launch tests for User Story 1 together:
task test:unit -- -run "Test.*externalref" -v ./pkg/sbom/externalref/...

# Launch both implementation changes together:
# Task: Reduce MaxElapsedTime in pkg/sbom/externalref/service.go
# Task: Reduce default timeout in pkg/sbom/externalref/service.go
```

---

## Implementation Strategy

### MVP First (User Story 1 Only)

1. Complete Phase 1: Setup
2. Complete Phase 2: Foundational (read current code)
3. Complete Phase 3: User Story 1 — core configuration change
4. **STOP and VALIDATE**: Test User Story 1 independently
5. Deploy/demo if ready

### Incremental Delivery

1. Complete Setup + Foundational → Foundation ready
2. Add User Story 1 → Test independently → Deploy/Demo (MVP!)
3. Add User Story 2 → Verify independently → Deploy/Demo
4. Each story adds value without breaking previous stories

### Parallel Team Strategy

With multiple developers:

1. Team completes Setup + Foundational together
2. Once Foundational is done:
   - Developer A: User Story 1 (core change)
   - Developer B: User Story 2 (verification)
3. US2 cannot start until US1 is complete (US2 verifies US1 behavior)

---

## Notes

- [P] tasks = different files, no dependencies
- [Story] label maps task to specific user story for traceability
- Each user story should be independently completable and testable
- Verify tests fail before implementing
- The existing test "returns error on server error (without retry)" explicitly passes a 30 s HTTP client with a 2-second context deadline — this test is intentionally bypassing the default timeout and should remain unchanged
- No changes needed to: `enricher.go`, `model.go`, `patcher.go`, `helpers_test.go`, `suite_test.go`
- Commit after each task or logical group
- Stop at any checkpoint to validate story independently