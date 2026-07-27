# Tasks: Batch Purl-Resolver Errors

**Input**: Design documents from `specs/011-batch-purl-resolver-errors/`

**Prerequisites**: plan.md (required), spec.md (required for user stories), research.md, data-model.md, contracts/

**Tests**: Test tasks are included. The constitution requires Test-Before-Merge, and spec.md/plan.md specify concrete unit and e2e test scenarios.

**Organization**: Tasks are grouped by user story to enable independent implementation and testing of each story.

## Format: `[ID] [P?] [Story] Description`

- **[P]**: Can run in parallel (different files, no dependencies)
- **[Story]**: Which user story this task belongs to (e.g., US1, US2)
- Include exact file paths in descriptions

## Path Conventions

- **Business logic**: `pkg/<domain>/`
- **Unit tests**: co-located with source files as `*_test.go`
- **Build**: `task build` (produces `./bin/werf`)
- **Unit tests**: `task test:unit`
- **E2E tests**: `task test:e2e` with Ginkgo label filters

---

## Phase 1: Setup (Shared Infrastructure)

**Purpose**: Feature branch creation and workspace preparation

- [X] T001 Create and switch to feature branch (current: `fix/sbom/group-purl-resolver-errors`) from the latest main

**Checkpoint**: Branch ready for implementation

---

## Phase 2: Foundational (Blocking Prerequisites)

**Purpose**: Core infrastructure that MUST be complete before any user story can be implemented

**⚠️ CRITICAL**: No user story work can begin until this phase is complete

- [X] T002 [P] Verify `ErrExternalRefEnrich` sentinel error exists in `pkg/sbom/externalref/patcher.go` (already added in a prior pass). Update `ExternalRefPatcher.Apply` to use `errors.Join(err, ErrExternalRefEnrich)` for wrapping the enricher error, so that `errors.Is(err, externalref.ErrExternalRefEnrich)` reliably detects PURL resolution errors through the chain. The apply method signature remains unchanged:

  ```go
  func (p *ExternalRefPatcher) Apply(ctx context.Context, bom *cdx.BOM) (*cdx.BOM, error) {
      if err := p.enricher.Enrich(ctx, bom); err != nil {
          return bom, fmt.Errorf("enrich external references: %w", errors.Join(err, ErrExternalRefEnrich))
      }
      return bom, nil
  }
  ```

**Note**: The sentinel `var ErrExternalRefEnrich = errors.New("enrich external references")` was already added. This task ensures it is present and that `Apply` joins it into the error chain.

**Checkpoint**: Foundation ready — sentinel verified and properly joined, user story implementation can begin

---

## Phase 3: User Story 1 — Component-Level `ComponentError` Type (Priority: P1) 🎯 MVP

**Goal**: `Enricher.Enrich` returns a `*ComponentError` type instead of a plain error. The `ComponentError` carries individual component failure details (name, error) inline in the error text, exposes `ComponentDetails()` for build-level aggregation, and removes `logboek.Error()` calls. The `Enricher.resolve` field is made public (→ `Resolve`) to enable unit test mocking.

**Independent Test**: Call `Enricher.Enrich` with a BOM containing components that fail PURL resolution. Verify that:
(a) the returned error is a `*ComponentError`
(b) `ComponentError.Error()` returns `"resolve external references: components failed:\n    - component: <name>: <err>\n..."`
(c) `ComponentError.ComponentDetails()` returns the raw detail lines for aggregation
(d) no `logboek.Error()` calls are made for individual component failures
(e) `Enricher.Resolve` (public field) works with a mock resolve function

### Tests for User Story 1

> **NOTE**: Write these tests FIRST, ensure they FAIL before implementation

- [ ] T003 [P] [US1] Write/update unit tests in `pkg/sbom/externalref/enricher_test.go` for the new `ComponentError` type. Cover these scenarios:
  - `ComponentError.Error()` returns the correct format with component names and errors
  - `ComponentError.ComponentDetails()` returns only the detail lines (without the summary line)
  - `ComponentError` implements `Unwrap()` so it works with standard error checks
  - `Enricher.Enrich` returns `*ComponentError` when some components fail PURL resolution
  - BOM with all components succeeding → no error returned (nil)
  - BOM with mixed success/failure → error only lists failed components
  - `Enricher.Resolve` (public field) can be injected with a custom mock resolve function via `NewEnricher` or by direct field assignment
  - Verify that `logboek.Error()` output does NOT contain individual component failure details

  Use Ginkgo + Gomega.

### Implementation for User Story 1

- [ ] T004 [P] [US1] Make `Enricher.resolve` a public field `Resolve` in `pkg/sbom/externalref/enricher.go` — rename the struct field from `resolve` to `Resolve`, update the `NewEnricher` constructor to set `Resolve`. The zero-value `Enricher{}` struct can also have `Resolve` set directly. The callers in `NewExternalRefPatcher` (patcher.go) must be updated to use `.Resolve` instead of `.resolve`.

- [ ] T005 [US1] Implement `ComponentError` type and refactor `Enricher.Enrich` in `pkg/sbom/externalref/enricher.go`:

  1. Define a `ComponentError` struct in a new file `pkg/sbom/externalref/component_error.go` (or inline in `enricher.go`):
     ```go
     type ComponentError struct {
         components []componentError
     }

     type componentError struct {
         name string
         err  error
     }

     func (e *ComponentError) Error() string {
         var buf strings.Builder
         buf.WriteString(fmt.Sprintf("resolve external references: components failed:\n"))
         for _, ce := range e.components {
             buf.WriteString(fmt.Sprintf("    - component: %s: %s\n", ce.name, ce.err))
         }
         return strings.TrimRight(buf.String(), "\n")
     }

     func (e *ComponentError) ComponentDetails() string {
         // Same as Error() but without the summary line — just the detail lines for build-level aggregation
         var buf strings.Builder
         for _, ce := range e.components {
             buf.WriteString(fmt.Sprintf("    - component: %s: %s\n", ce.name, ce.err))
         }
         return strings.TrimRight(buf.String(), "\n")
     }

     func (e *ComponentError) Unwrap() error {
         if len(e.components) == 0 {
             return nil
         }
         return e.components[0].err
     }
     ```

  2. In `Enricher.Enrich`, remove the `logboek.Error()` per-component logging loop and the generic `fmt.Errorf("resolve external references: %d of %d components failed")`. Instead, return a `*ComponentError` with the collected failures.

  3. Keep the `logboek.Context(ctx).Debug().LogF(...)` line for the success path — it is non-intrusive debugging output.

**Checkpoint**: Component-level error details now flow through the error chain as a typed `*ComponentError`. Build-level aggregation can consume `ComponentDetails()`.

---

## Phase 4: User Story 1 — Build-Level Hierarchical Error Aggregation (Priority: P1) 🎯 MVP

**Goal**: `convergeSbomByImagesSets` accumulates PURL resolution errors across ALL image sets and returns a single hierarchical aggregated error using a `buildAggregatedPurlError` helper. The format is:

```
resolve external references: N of M images failed:
  - image: <image-name>:
    - component: <component-name>: <error>
```

**Independent Test**: Create a test with multiple image sets where some images have PURL failures. Verify that:
(a) all images across all sets are attempted regardless of individual failures
(b) a single hierarchical error is returned after ALL sets are processed
(c) each failed image has a `"  - image: <name>:"` line with `"    - component:"` sub-lines
(d) the total count of failed images and total images is correct
(e) a non-PURL error in any set stops the build immediately and is NOT aggregated

### Tests for User Story 1

> **NOTE**: Write these tests FIRST, ensure they FAIL before implementation

- [ ] T006 [P] [US1] Write unit tests in `pkg/build/build_phase_purl_test.go` for global build-level hierarchical error aggregation using Ginkgo + Gomega. Cover these scenarios:
  - Happy path across multiple sets: two image sets, all images succeed → no error returned
  - Single set mixed failures: 1 set with 3 images, 2 fail PURL resolution → aggregated error contains `"resolve external references: 2 of 3 images failed"` and each failed image has `"  - image:"` lines with `"    - component:"` sub-lines
  - Multiple sets with failures: 2 image sets, first set has 1 failure out of 2 images, second set has 1 failure out of 1 image → aggregated error shows `"2 of 3 images failed"` with both image names and their component details (global aggregation across all sets)
  - All fail across sets: 2 image sets, each with 1 image, both fail → `"2 of 2 images failed"`
  - Single image fail: 1 of 1 images fails → `"1 of 1 images failed"` with `"  - image:"` details
  - Non-PURL error: pre-condition failure → immediate error (not aggregated, `DoTasks` closure returns the error immediately)
  - Empty image sets: no images across all sets → no error
  - Successful images preserved: succeeding images have valid SBOMs even when others fail
  - `buildAggregatedPurlError` helper builds correct format given a `sync.Map` of image→`ComponentDetails()` strings

  Use the mock helpers created below in T007.

- [ ] T007 [P] [US1] Create test helpers and mock infrastructure in `pkg/build/build_phase_purl_test.go` — add helpers for constructing simulated image sets (with helpers to create multiple sets), a mock `ExternalRefPatcher` that returns controlled PURL errors wrapping `externalref.ErrExternalRefEnrich` (with realistic `*ComponentError` details in the error text via `fmt.Errorf`), pre-condition errors, and success cases.

### Implementation for User Story 1

- [ ] T008 [US1] Refactor `convergeSbomByImagesSets` in `pkg/build/build_phase.go` to accumulate PURL errors globally across ALL image sets:
  - Declare `var purlErrors sync.Map` and `var totalImages int` BEFORE the `for` loop (outside all image sets)
  - Inside the `for` loop, add the per-set image count to `totalImages` (`totalImages += len(names)`)
  - In the `DoTasks` closure, detect PURL errors via `errors.Is(err, externalref.ErrExternalRefEnrich)`, accumulate the image name and the full error into the shared `purlErrors` sync.Map, and return nil (so other images continue)
  - Non-PURL errors MUST still return immediately (stopping the current set via `parallel.DoTasks` error propagation)
  - Do NOT return early with an aggregated error after each set

- [ ] T009 [US1] After the `for` loop (ALL image sets processed) in `pkg/build/build_phase.go`, call a helper function `buildAggregatedPurlError(purlErrors *sync.Map, totalImages int) error` that builds the hierarchical aggregated error:

  ```go
  func buildAggregatedPurlError(purlErrors *sync.Map, totalImages int) error {
      var imageErrors []string
      purlErrors.Range(func(key, value interface{}) bool {
          imageName := key.(string)
          err := value.(error)
          // The err already contains ComponentError with component details.
          // Extract component details using ComponentDetails type assertion.
          var compErr *externalref.ComponentError
          if errors.As(err, &compErr) {
              imageErrors = append(imageErrors, fmt.Sprintf("  - image: %s:\n%s", imageName, compErr.ComponentDetails()))
          } else {
              imageErrors = append(imageErrors, fmt.Sprintf("  - image: %s:\n    - error: %s", imageName, err))
          }
          return true
      })
      sort.Strings(imageErrors) // deterministic output
      return fmt.Errorf("resolve external references: %d of %d images failed:\n%s", len(imageErrors), totalImages, strings.Join(imageErrors, "\n"))
  }
  ```

  If no errors accumulated (`purlErrors` is empty), return nil.

**Checkpoint**: Build-level hierarchical error aggregation is complete. User Story 1 should be fully functional. Run `task build` and `task test:unit` to verify.

---

## Phase 5: User Story 2 — E2E Test with 3 Images and `httptest` Mock Server (Priority: P2)

**Goal**: A Ginkgo e2e test at `test/e2e/sbom/purl_resolver_errors_test.go` validates the full feature end-to-end: 3 images with mixed PURL resolution outcomes, a custom `httptest.Server` mock returning 404 for specific packages (`curl`, `openssl`) and 200 for `jq`, fixtures at `test/e2e/sbom/_fixtures/purl_resolver_errors/`, the build fails with a single hierarchical aggregated error.

**Independent Test**: Run `task test:e2e -- paths="./test/e2e/sbom/..." labelFilter="purl-resolver-errors"`. The test creates a repo, runs `werf build`, and verifies the aggregated error contains all expected image names and component details, while `image-ok` is unaffected.

### Tests for User Story 2

- [ ] T010 [P] [US2] Create e2e test file at `test/e2e/sbom/purl_resolver_errors_test.go` using Ginkgo and a custom `httptest.Server`. The test scenario:
  - Image 1 `image-fail-all`: 2 OS PM packages `curl==8.12.1` and `openssl==3.6.2`, both fail (mock returns 404)
  - Image 2 `image-fail-partial`: 2 OS PM packages `curl==8.12.1` (fails) and `jq==1.8.1` (succeeds)
  - Image 3 `image-ok`: 1 OS PM package `jq==1.8.1` (succeeds)
  - Create an `httptest.Server` with a handler that inspects the PURL and returns 200 for `jq` and 404 for `curl`/`openssl`
  - Set `WERF_EXTERNAL_REFS_SERVER_URL` to the mock server URL
  - Create fixtures at `test/e2e/sbom/_fixtures/purl_resolver_errors/` with:
    - `werf.yaml` defining the 3 images with `apt` packages
    - `Dockerfile` for each image
    - `werf-giterminism.yaml` if needed to bypass strict mode
  - Assert the build fails with a single aggregated error containing:
    - `"resolve external references: 2 of 3 images failed"` header
    - `"  - image: image-fail-all"` with 2 component failure lines
    - `"  - image: image-fail-partial"` with 1 component failure line
    - Individual component names: `curl`, `openssl`
    - Does NOT contain `"image: image-ok"`
  - Assert that `image-ok` SBOM has valid external references (e.g., `jq` resolved to an external URL)

  Follow the existing e2e test patterns in `test/e2e/sbom/` for repository setup, build execution, and SBOM inspection.

**Checkpoint**: E2e test passes. Full feature validated.

---

## Phase 6: Polish & Cross-Cutting Concerns

**Purpose**: Verification and quality assurance

- [ ] T011 Run `task test:unit` to verify all unit tests pass (enricher tests + build phase PURL tests)
- [ ] T012 Commit changes per Conventional Commits format: `fix(sbom): carry component failure details inline in PURL error text`

---

## Dependencies & Execution Order

### Phase Dependencies

- **Setup (Phase 1)**: No dependencies — can start immediately
- **Foundational (Phase 2)**: Depends on Setup completion — **BLOCKS** all user stories
- **US1 — ComponentError type (Phase 3)**: Depends on Foundational phase completion
- **US1 — Build-level aggregation (Phase 4)**: Depends on Phase 3 (build-level aggregation consumes `*ComponentError` from the enricher)
- **US2 — E2E test (Phase 5)**: Depends on Phase 4 (e2e test validates the full pipeline)
- **Polish (Phase 6)**: Depends on all completed phases

### User Story Dependencies

- **US1 (P1)**: No dependencies on other stories — can be fully completed first (MVP)
- **US2 (P2)**: Depends on US1 completion (validates US1 end-to-end)

### Within Each User Story

- **US1 (Component)**: Tests (T003) → `Resolve` public (T004) → `ComponentError` + refactor (T005)
- **US1 (Build)**: Test helpers (T007) → Tests (T006) → Accumulation (T008) → Helper (T009)
- **US2 (E2E)**: Test file + fixtures (T010) — single task

### Parallel Opportunities

- **Phase 2**: Single task (T002) — no parallel opportunities
- **Phase 3**: T003 (tests) and T004 (public `Resolve`) can run in parallel — different files; T005 depends on both
- **Phase 4**: T006 (tests) and T007 (test helpers) can run in parallel — same file but logically independent; T008, T009 must run sequentially (modify same file `build_phase.go`)
- **Phase 5**: Single task (T010) — no parallel opportunities
- All phases are sequential (each depends on the previous)

---

## Parallel Example: User Story 1

```bash
# --- Component-level (Phase 3) ---
# Step 1: Make Resolve public + write tests (in parallel)
# Edit pkg/sbom/externalref/enricher.go — rename resolve to Resolve
# Edit pkg/sbom/externalref/enricher_test.go — write tests for ComponentError

# Step 2: Implement ComponentError + refactor Enrich
# Edit pkg/sbom/externalref/component_error.go — define ComponentError type
# Edit pkg/sbom/externalref/enricher.go — return *ComponentError, remove logboek calls

# Step 3: Run tests
task test:unit -- -run "TestBuild" ./pkg/sbom/externalref/...

# --- Build-level (Phase 4) ---
# Step 4: Create test helpers + write tests (in parallel)
# Edit pkg/build/build_phase_purl_test.go — add mock helpers
# Edit pkg/build/build_phase_purl_test.go — add aggregation tests

# Step 5: Implement global aggregation + buildAggregatedPurlError helper
# Edit pkg/build/build_phase.go — refactor convergeSbomByImagesSets
# Edit pkg/build/build_phase.go — add buildAggregatedPurlError helper

# Step 6: Run all unit tests
task test:unit
```

---

## Implementation Strategy

### MVP First (User Story 1 Only)

1. Complete Phase 1: Setup — branch ready
2. Complete Phase 2: Foundational — sentinel + errors.Join in patcher.go
3. Complete Phase 3: US1 (Component) — `ComponentError` type + enricher refactor
4. Complete Phase 4: US1 (Build) — global aggregation + `buildAggregatedPurlError`
5. **STOP and VALIDATE**: Run `task test:unit`, verify US1 acceptance scenarios independently
6. (Optional) Phase 5: US2 — E2E test

### Incremental Delivery

1. Complete Setup + Foundational → Foundation ready
2. Add US1 (ComponentError) → Component errors carry typed details
3. Add US1 (Build aggregation) → Single hierarchical error across entire build (MVP!)
4. Add US2 (E2E test) → Full end-to-end verification

---

## Notes

- [P] tasks = different files, no dependencies
- [Story] label maps task to specific user story for traceability
- Each user story should be independently completable and testable
- Verify tests fail before implementing (TDD approach)
- Commit after each task or logical group
- Stop at any checkpoint to validate story independently
- Avoid: vague tasks, same file conflicts, cross-story dependencies