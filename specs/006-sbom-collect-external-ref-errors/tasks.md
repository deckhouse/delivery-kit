# Tasks: Collect External Reference Errors

**Input**: Existing implementation in `pkg/sbom/externalref/` on branch `feat/sbom/collect-external-ref-errors`

**Organization**: All tasks are completed — the feature already exists.

## Format: `[ID] [P?] [Story] Description`

- **[P]**: Can run in parallel (different files, no dependencies)
- **[Story]**: Which user story this task belongs to (e.g., US1, US2)
- All tasks marked `[x]` since the feature is already implemented

---

## Extract Per-Component Logic

- [x] T001 [P] [US1] Extract per-component enrichment into `enrichComponent(ctx, comp, seen)` method in `pkg/sbom/externalref/enricher.go` — moves existing inline logic (PURL validation, resolve call, ref kind validation, external ref append, seen tracking) into a named method that returns an error

---

## Change Concurrency Semantics

- [x] T002 [US1] Replace `errgroup.WithContext(ctx)` with plain `errgroup.Group` in `pkg/sbom/externalref/enricher.go` — this ensures all goroutines continue processing even when individual components fail, instead of cancelling the context on the first error

---

## Error Collection and Aggregation

- [x] T003 [US1] Add `componentError` type and error collection in `pkg/sbom/externalref/enricher.go` — populate `compErrs` slice from goroutine closures, aggregate with `lo.Compact`, log each failure via `logboek.Error()`, return `fmt.Errorf("resolve external references: %d of %d components failed", ...)`

---

## Update Unit Tests

- [x] T004 [P] [US1] Update test cases in `pkg/sbom/externalref/enricher_test.go` to match new error message format (`"N of M components failed"` instead of per-component error strings), rename entries to reflect new behaviour, add new test case for "collects every failed component instead of stopping at the first"
- [x] T005 [P] [US1] Verify existing test cases still pass and cover: happy path (all succeed), nil/empty components, OS type skipping, existing refs preservation, deduplication, `ExternalRefPatcher` error wrapping

---

## Summary

| Status | Total Tasks |
|--------|-------------|
| ✅ Completed | 5 |
| ⏳ Pending | 0 |
| **Total** | **5** |

## Gaps Identified

- None — the change has adequate test coverage including single-failure, multi-failure, and mixed success/failure scenarios; the `ExternalRefPatcher` wrapper is also tested for both success and error cases