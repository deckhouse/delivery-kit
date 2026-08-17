# Tasks: SBOM Converge Failure Semantics

**Input**: Design documents from `/specs/017-sbom-converge-failure-semantics/`

**Prerequisites**: plan.md, spec.md, research.md, data-model.md, contracts/README.md, quickstart.md

**Tests**: Included — constitution mandates Test-Before-Merge (Ginkgo + Gomega, table-driven, co-located).

**Organization**: Tasks are grouped by user story to enable independent implementation and testing of each story.

## Format: `[ID] [P?] [Story] Description`

- **[P]**: Can run in parallel (different files, no dependencies)
- **[Story]**: Which user story this task belongs to (US1, US2, US3)
- Include exact file paths in descriptions

## Path Conventions

- **Business logic**: `pkg/build/`, `pkg/sbom/externalref/`, `pkg/oci/artifact/`
- **Unit tests**: co-located with source files as `*_test.go`
- **E2E tests**: `test/e2e/build/` (SBOM suites)

## Build & Test Commands

- **Build**: `task build` (produces `./bin/werf`)
- **Unit tests**: `task test:unit paths="./pkg/sbom/externalref/..."` / `paths="./pkg/build/..."`
- **E2E tests**: `task test:e2e paths="./test/e2e/..." labelFilter="sbom"`. NEVER place `KEY=VALUE` after `--` separator.
  - Environment is pre-configured — `task test:setup:environment` has already been executed. Do not skip e2e tests citing environment setup.
- **Formatting**: `task format`

---

## Phase 1: Setup

**Purpose**: Baseline verification — existing project, no scaffolding needed.

- [ ] T001 Verify baseline is green before changes: `task build` and `task test:unit paths="./pkg/sbom/externalref/... ./pkg/build/..."`; record any pre-existing failures in the PR notes

---

## Phase 2: Foundational (Blocking Prerequisites)

**Purpose**: The deferred aggregated report and the extended failure-record shape are prerequisites for both US1 and US2 acceptance scenarios (FR-009, FR-005).

**⚠️ CRITICAL**: No user story work can begin until this phase is complete.

- [ ] T002 Extend `purlErrors` entries from bare details strings to a failure-record struct (`details`, `rootImage`, `rootCause` per data-model.md) in `pkg/build/build_phase.go` (`convergeSbomByImagesSets`, `buildAggregatedPurlError`); direct failures set `rootImage` = own name; report output for direct failures must stay byte-identical to today's format
- [ ] T003 Emit the aggregated PURL report on every exit path of `convergeSbomByImagesSets` via `defer` in `pkg/build/build_phase.go`: happy path returns the aggregated error as today; on a hard error the report is logged via logboek and the hard error stays terminal (research R5)
- [ ] T004 Add unit tests for T002+T003 in `pkg/build/build_phase_purl_test.go`: report format unchanged for direct failures; report emitted when a hard non-PURL error interrupts a set; hard error remains the terminal error (`errors.Is` identity preserved)

**Checkpoint**: Foundation ready — user story implementation can now begin.

---

## Phase 3: User Story 1 - Dependent image failure reports the real cause (Priority: P1) 🎯 MVP

**Goal**: An image whose base failed PURL enrichment in this run is skipped with the base's actual error as the cause (transitively), the misleading "rebuild it with SBOM generation enabled" advice disappears for in-run bases, and the aggregated report lists skipped images.

**Independent Test**: Unit: two-set fixture where set-1 image fails enrich → set-2 dependent is skipped with root cause, report contains both entries, no misleading advice. E2E: two-image project (`b` fromImage `a`) with mock resolver failing `a`'s package.

### Tests for User Story 1 (write first, ensure they FAIL)

- [ ] T005 [US1] Add failing unit tests in `pkg/build/build_phase_purl_test.go`: (a) dependent of a failed image is skipped with skip record referencing root image and cause; (b) transitive chain A→B→C reports A as root cause for C; (c) aggregated report renders skip entries as `skipped: SBOM for base image "<root>" was not generated: <cause>` (contracts/README.md format); (d) multiplatform — failure of one platform of a name marks the whole name failed
- [ ] T006 [P] [US1] Add failing unit test in `pkg/build/sbom_step_error_test.go`: base-SBOM-missing advice ("rebuild it with SBOM generation enabled") is produced only when the base was NOT processed by the current run

### Implementation for User Story 1

- [ ] T007 [US1] Implement dependency skip in `pkg/build/build_phase.go`: before converging an image in `convergeSbomByImagesSets`/`convergeImageSbom`, look up `img.GetBaseImageName()` in the failure map; on hit, record a skip record (copying `rootImage`/`rootCause` from the base's entry for transitivity) and skip converge for that image name (FR-005/006/007)
- [ ] T008 [US1] Render skip records in `buildAggregatedPurlError` in `pkg/build/build_phase.go` under the existing hierarchical format; summary line counts skipped images in N (research R8)
- [ ] T009 [US1] Gate the misleading advice in `pkg/build/build_phase.go` `collectBaseImageSbom` + `pkg/build/sbom_step.go` `baseSbomMissingError`: when the base image is present in this run's failure map, return the real cause (`SBOM for base image %q was not generated: <cause>`) instead of the rebuild advice (FR-008); keep advice for genuinely foreign bases
- [ ] T010 [US1] Verify T005/T006 tests pass; run `task test:unit paths="./pkg/build/..."`; run test-the-tests mutation check on the new tests (`.agents/skills/test-the-tests/SKILL.md`)

**Checkpoint**: US1 fully functional — dependent failures report real causes, report always printed.

---

## Phase 4: User Story 2 - Unavailable resolver fails fast (Priority: P2)

**Goal**: After a fixed number of consecutive infrastructure failures, the resolver is declared unavailable for the rest of the build: no further attempts or retries, one terminal `PURL resolver unavailable at <endpoint>: <last error>` error plus the accumulated report.

**Independent Test**: Unit: mock server returning only timeouts/5xx trips the breaker after the threshold; subsequent `Resolve` calls fail instantly; content failures (404) never trip it. Integration-style: multi-image converge against a dead endpoint fails after threshold, not after per-image budgets.

### Tests for User Story 2 (write first, ensure they FAIL)

- [ ] T011 [P] [US2] Add failing classification tests in `pkg/sbom/externalref/service_test.go` (DescribeTable): 404/other-4xx/empty-URL/parse-error → content; transport error (unreachable server)/429/5xx → infra; classification observable on the error returned by `Service.Resolve` via `errors.As`
- [ ] T012 [P] [US2] Add failing breaker tests in new `pkg/sbom/externalref/breaker_test.go`: trips after exactly threshold consecutive infra failures; success resets counter; content failures don't count; tripped state latches; `Allow()` returns `ErrResolverUnavailable` wrapping endpoint + last infra error; concurrent `Record` calls are safe (race-detector exercised)
- [ ] T013 [US2] Add failing build-phase test in `pkg/build/build_phase_purl_test.go`: worker error matching `errors.Is(err, externalref.ErrResolverUnavailable)` terminates converge as a hard error AND the accumulated report is still emitted (relies on T003)

### Implementation for User Story 2

- [ ] T014 [US2] Introduce `FailureClass` (string enum: `FailureClassContent`, `FailureClassInfra`) and a classified error type wrapping the cause, produced inside `doResolve` in `pkg/sbom/externalref/service.go` alongside the existing `backoff.Permanent` decisions (research R1, data-model.md); preserve current retry behavior exactly
- [ ] T015 [US2] Implement `ResolverBreaker` (mutex-guarded consecutive-infra counter, latched trip, unexported threshold constant = 5) and sentinel `ErrResolverUnavailable` in new `pkg/sbom/externalref/breaker.go`; `Service.Resolve` consults `Allow()` before the retry loop and calls `Record`/`RecordSuccess` after each attempt outcome (research R2/R3); breaker optional in `ServiceConfig` (nil = disabled) so existing callers/tests are unaffected
- [ ] T016 [US2] Plumb the breaker: add options struct to `NewExternalRefPatcher` in `pkg/sbom/externalref/patcher.go` (options last, per CODESTYLE); construct one breaker per build in `convergeSbomByImagesSets` in `pkg/build/build_phase.go` and pass it through the patcher creation at `convergePlatformImageSbom`
- [ ] T017 [US2] Handle the trip in `pkg/build/build_phase.go` `convergeSbomByImagesSets`: `errors.Is(err, externalref.ErrResolverUnavailable)` → hard error path (terminal, reported once), deferred report still emitted; keep `logPurlResolverHelpHint` on this path
- [ ] T018 [US2] Verify T011–T013 pass; run `task test:unit paths="./pkg/sbom/externalref/... ./pkg/build/..."`; run test-the-tests mutation check on breaker tests

**Checkpoint**: US1 and US2 work independently — outage fails fast with one clear error.

---

## Phase 5: User Story 3 - SBOM log output names causes and targets (Priority: P3)

**Goal**: Five log-quality fixes: cause next to FAILED, GOST warning once per process, contextualized multiple-entries warning, repo address in copy messages, timed external-ref resolution section.

**Independent Test**: Unit tests intercepting logboek output where practical; manual/e2e log inspection per quickstart.md US3 scenario.

### Tests for User Story 3 (write first where output is capturable)

- [ ] T019 [P] [US3] Add failing test in `pkg/build/sbom_step_test.go`: GOST experimental warning emitted at most once across multiple `prepareGostComponents` invocations
- [ ] T020 [P] [US3] Add failing test in `pkg/oci/artifact/fallback_test.go` (create if absent, next to `pkg/oci/artifact/fallback.go`): multiple-entries warning names the requesting image, the image names carried by entries, and the selected entry

### Implementation for User Story 3

- [ ] T021 [US3] Print the deferred enrichment error inside the failing image's log block in `pkg/build/build_phase.go` (worker in `convergeSbomByImagesSets`, at the classification point before deferral) so FAILED sits next to its cause (FR-010, research R6.1)
- [ ] T022 [P] [US3] Guard the GOST experimental warning with `sync.Once` in `pkg/build/sbom_step.go` `prepareGostComponents` (FR-011)
- [ ] T023 [P] [US3] Contextualize the multiple-entries warning in `pkg/oci/artifact/fallback.go` `GetAttached`: include requesting image (when known), entry image names from annotations, and the selected entry (FR-012)
- [ ] T024 [P] [US3] Add the final-repo address to the `Copy SBOM artifacts into the final repo` message in `pkg/build/sbom_step.go` `PropagateArtifacts` (cache message already prints the address) (FR-013)
- [ ] T025 [US3] Wrap external-ref resolution in its own named `LogProcess` with timer inside the patcher loop in `pkg/build/sbom_step.go` `ConvergeWithMerge` (special-case the external-ref patcher at the call site; patcher interface unchanged — research R6.6) (FR-014)
- [ ] T026 [US3] Verify T019/T020 pass; run `task test:unit paths="./pkg/build/... ./pkg/oci/artifact/..."`

**Checkpoint**: All user stories independently functional.

---

## Phase 6: Polish & Cross-Cutting Concerns

- [ ] T027 Full verification sequence in order: `task format`, `task build`, `task lint`, `task test:unit` (unscoped)
- [ ] T028 E2E validation: `task test:e2e paths="./test/e2e/..." labelFilter="sbom"` on the Linux environment; walk quickstart.md US1/US2/US3 scenarios and confirm contracts/README.md output contracts
- [ ] T029 [P] Update `wiki/pages/error-aggregation-strategy.md`: skip-entry kind in the report format, report-on-every-exit-path guarantee, breaker interaction (cross-reference `purl-resolution.md`)
- [ ] T030 Re-check spec success criteria SC-001…SC-006 against actual behavior and mark the feature converged (input problem `specs/017-sbom-converge-failure-semantics/PROBLEM.md` fully addressed; operational follow-ups remain out of scope)

---

## Dependencies & Execution Order

### Phase Dependencies

- **Setup (Phase 1)**: none — start immediately
- **Foundational (Phase 2)**: after Setup — BLOCKS all user stories (T002 → T003 → T004)
- **US1 (Phase 3)**: after Foundational; no dependency on US2/US3
- **US2 (Phase 4)**: after Foundational; T013/T017 rely on T003 (defer) only — independent of US1
- **US3 (Phase 5)**: after Foundational; T021 touches the same worker block as US1's T007 — if run in parallel with US1, coordinate edits in `convergeSbomByImagesSets`; all other US3 tasks independent
- **Polish (Phase 6)**: after all desired stories

### Within Each User Story

- Tests written first and failing before implementation
- `pkg/sbom/externalref` types before `pkg/build` plumbing (US2: T014 → T015 → T016 → T017)
- Story complete (including test-the-tests check) before moving to next priority

### Parallel Opportunities

- T005 ∥ T006 (different test files)
- T011 ∥ T012 (different test files); T014 ∥ nothing (same file as T015's neighbors — keep sequential T014 → T015)
- T019 ∥ T020; T022 ∥ T023 ∥ T024 (different files)
- US2 can proceed in parallel with US1 by a second developer (different primary files; only T017 and T007 share `build_phase.go` — merge carefully)

---

## Parallel Example: User Story 2

```bash
# Failing tests first, in parallel (different files):
Task: "T011 classification tests in pkg/sbom/externalref/service_test.go"
Task: "T012 breaker tests in pkg/sbom/externalref/breaker_test.go"

# Then implementation sequentially within the package:
# T014 (classification) → T015 (breaker) → T016 (plumbing) → T017 (build phase)
```

---

## Implementation Strategy

### MVP First (User Story 1 Only)

1. Phase 1 → Phase 2 (foundational report/record changes)
2. Phase 3 (US1) — fixes the observed production failure
3. **STOP and VALIDATE**: unit + e2e US1 scenario; this alone is shippable
4. Phase 4 (US2) — outage fail-fast
5. Phase 5 (US3) — log quality
6. Phase 6 — polish, e2e, wiki

### Notes

- Commit after each task or logical group (git-conventions skill before every commit)
- `task format` before `task build` when verifying — format mutates files
- No new CLI flags/config anywhere (FR-015); `task doc:gen` not needed (no command help changes)
