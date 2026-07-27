# Tasks: Batch Purl-Resolver Errors

**Input**: Design documents from `specs/011-batch-purl-resolver-errors/`

**Prerequisites**: plan.md (required), spec.md (required for user stories), research.md, data-model.md, contracts/

**Tests**: Test tasks are included. The constitution requires Test-Before-Merge, and quickstart.md specifies concrete test scenarios.

**Organization**: Tasks are grouped by user story to enable independent implementation and testing of each story.

## Format: `[ID] [P?] [Story] Description`

- **[P]**: Can run in parallel (different files, no dependencies)
- **[Story]**: Which user story this task belongs to (e.g., US1)
- Include exact file paths in descriptions

## Path Conventions

- **Business logic**: `pkg/<domain>/`
- **Unit tests**: co-located with source files as `*_test.go`
- **Build**: `task build` (produces `./bin/werf`)
- **Unit tests**: `task test:unit`

---

## Phase 1: Setup (Shared Infrastructure)

**Purpose**: Feature branch creation and workspace preparation

- [X] T001 Create and switch to feature branch (current: `fix/sbom/group-purl-resolver-errors`) from the latest main

**Checkpoint**: Branch ready for implementation

---

## Phase 2: Foundational (Blocking Prerequisites)

**Purpose**: Core infrastructure that MUST be complete before User Story 1 can be implemented

**⚠️ CRITICAL**: No user story work can begin until this phase is complete

- [X] T002 [P] Create test helpers and mock infrastructure in `pkg/build/build_phase_test.go` — add helpers for constructing simulated image sets (with helpers to create multiple sets), a mock `ExternalRefPatcher` that returns controlled errors (PURL resolution errors wrapping `externalref.ErrExternalRefEnrich`, pre-condition errors, and success), and a Ginkgo `Describe` container setup for the `convergeSbomByImagesSets` tests.
  
  **Note**: `ErrExternalRefEnrich` sentinel was already added in `pkg/sbom/externalref/patcher.go` in a prior pass — verify it exists and is correct.

**Checkpoint**: Foundation ready — sentinel error is verified, test infrastructure is in place, user story implementation can begin

---

## Phase 3: User Story 1 - See All PURL Resolution Failures in a Single Build (Priority: P1) 🎯 MVP

**Goal**: When building container images, PURL resolution errors from ALL images are collected and reported in a single aggregated message, rather than stopping the build at the first failure.

**Independent Test**: Create a project with multiple images where a subset has unresolvable PURLs, run the build, and verify that: (a) all images are attempted for PURL resolution regardless of individual failures, (b) the build fails with a single aggregated error listing all failures, (c) each failure includes the image name and the underlying error detail.

### Tests for User Story 1

> **NOTE: Write these tests FIRST, ensure they FAIL before implementation**

- [ ] T004 [P] [US1] Write unit tests for error aggregation in `pkg/build/build_phase_test.go` using Ginkgo + Gomega. Cover these scenarios:
  - Happy path across multiple sets: two image sets, all images succeed → no error returned
  - Single set mixed failures: 1 set with 3 images, 2 fail PURL resolution → aggregated error contains `"resolve external references: 2 of 3 images failed"` and individual error messages for each failed image
  - Multiple sets with failures: 2 image sets, first set has 1 failure out of 2 images, second set has 1 failure out of 1 image → aggregated error contains `"resolve external references: 2 of 3 images failed"` and individual error details for both failures (global aggregation across all sets)
  - All fail across sets: 2 image sets, each with 1 image, both fail → aggregated error contains `"resolve external references: 2 of 2 images failed"`
  - Single image fail: 1 of 1 images fails → aggregated error string contains `"resolve external references: 1 of 1 images failed"`
  - Non-PURL error: pre-condition failure (e.g., `NewExternalRefPatcher` failure) → immediate error (not aggregated)
  - Empty image sets: no images across all sets → no error
  - Successful images preserved: succeeding images have valid SBOMs even when others fail

  Use the mock helpers created in T002.

### Implementation for User Story 1

- [X] T005 [US1] Refactor `convergeSbomByImagesSets` in `pkg/build/build_phase.go` to accumulate PURL errors globally across ALL image sets:
  - Declare `var purlErrors sync.Map` and `var totalImages int` BEFORE the `for` loop (outside all image sets)
  - Inside the `for` loop, add the per-set image count to `totalImages` (`totalImages += len(names)`)
  - Inside the `DoTasks` closure, detect PURL errors via `errors.Is(err, externalref.ErrExternalRefEnrich)` and accumulate them into the shared `purlErrors` sync.Map (same as current behavior but the Map is shared across all sets)
  - Non-PURL errors MUST still return immediately (stopping the current set via `parallel.DoTasks` error propagation)
  - Do NOT return early with an aggregated error after each set

- [X] T006 [US1] After the `for` loop (ALL image sets processed) in `pkg/build/build_phase.go`, build a single composite error from all accumulated PURL errors:
  - Collect all error values from `purlErrors` via `.Range()` into a `[]error` slice
  - If any errors exist, use `errors.Join(purlErrorSlice...)` to combine them into one error, then wrap it with `fmt.Errorf("resolve external references: %d of %d images failed: %w", errorCount, totalImages, errs)` to preserve the format contract
  - If no errors, return nil

  Example:
  ```go
  var errs []error
  purlErrors.Range(func(key, value interface{}) bool {
      errs = append(errs, value.(error))
      return true
  })
  if len(errs) > 0 {
      return fmt.Errorf("resolve external references: %d of %d images failed: %w", len(errs), totalImages, errors.Join(errs...))
  }
  ```

  The joined error preserves all individual error messages. When printed, each error is separated by a newline by `errors.Join`. The sentinel `ErrExternalRefEnrich` remains detectable via `errors.Is` on individual entries but NOT on the joined result (the count+format message is the primary contract).

**Checkpoint**: At this point, User Story 1 should be fully functional and testable independently

---

## Phase 4: Polish & Cross-Cutting Concerns

**Purpose**: Verification and quality assurance

- [X] T008 Run `task test:unit` to verify all tests pass (including new tests for error aggregation)
- [ ] T009 Commit changes per Conventional Commits format: `feat(build): batch PURL resolver errors across image set`

---

## Dependencies & Execution Order

### Phase Dependencies

- **Setup (Phase 1)**: No dependencies — can start immediately
- **Foundational (Phase 2)**: Depends on Setup completion — **BLOCKS** all user stories
- **User Story 1 (Phase 3)**: Depends on Foundational phase completion
- **Polish (Phase 4)**: Depends on User Story 1 completion

### User Story Dependencies

- **User Story 1 (P1)**: Can start after Foundational (Phase 2) — No dependencies on other stories

### Within User Story 1

- Tests (T004) MUST be written and FAIL before implementation
- Test helpers (T002) before user story implementation
- Error detection + accumulation (T005) before aggregation (T006)

### Parallel Opportunities

- **Phase 2**: Only one task (T002 — test helpers), no parallel opportunities within this phase
- **Phase 3**: T005, T006 must run sequentially (they modify the same file `pkg/build/build_phase.go`)
- All phases are sequential (each depends on the previous)

---

## Parallel Example: User Story 1

```bash
# Step 1: Write tests first
# Edit pkg/build/build_phase_test.go — write Ginkgo tests for all scenarios
# Verify they fail:
task test:unit -- -run "TestBuild" ./pkg/build/

# Step 2: Implement error accumulation across all image sets
# Edit pkg/build/build_phase.go — refactor convergeSbomByImagesSets

# Step 3: Run tests to verify
task test:unit -- -run "TestBuild" ./pkg/build/

# Step 4: Finalize
task test:unit
```

---

## Implementation Strategy

### MVP First (User Story 1 Only)

1. Complete Phase 1: Setup — create branch
2. Complete Phase 2: Foundational — verify sentinel exists and create test helpers
3. Complete Phase 3: User Story 1 — write tests, implement error accumulation
4. **STOP and VALIDATE**: Test User Story 1 independently
5. Complete Phase 4: Polish — test, commit

### Incremental Delivery

1. Complete Setup + Foundational → Foundation ready
2. Add User Story 1 → Test independently → Commit (MVP!)

---

## Notes

- [P] tasks = different files, no dependencies
- [Story] label maps task to specific user story for traceability
- User Story 1 should be independently completable and testable
- Verify tests fail before implementing
- Commit after each task or logical group
- Stop at any checkpoint to validate story independently
- Avoid: vague tasks, same file conflicts, cross-story dependencies