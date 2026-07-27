# Quickstart: Reduce PURL Resolver Retries Duration

## Prerequisites

- Go 1.24+
- Working `task` setup (see [Taskfile.yml](../../Taskfile.yml))
- No external dependencies needed — the PURL resolution service can be mocked with `httptest`

## Validation Scenarios

### Scenario 1: Retry budget reduction (10 s max)

**Goal**: Verify that `Service.Resolve` exhausts its retry budget within ~10 s (not 30 s).

**Steps**:
1. Run the existing unit test that exercises retry behavior:
   ```bash
   task test:unit -- -run "Test.*externalref" -v ./pkg/sbom/externalref/...
   ```
2. Check that the test `"returns error on server error (without retry)"` passes within the expected time.

**Expected**: All tests pass. The retry budget is now 10 s instead of 30 s.

### Scenario 2: HTTP client timeout (5 s default)

**Goal**: Verify that `NewService` with default config creates a client with 5 s timeout.

**Steps**:
1. Inspect the default timeout assignment in `NewService`:
   ```go
   // After change: timeout = 5 * time.Second
   ```
2. Run the unit test suite to verify no regressions:
   ```bash
   task test:unit ./pkg/sbom/externalref/...
   ```

**Expected**: Default timeout is 5 s. Tests pass.

### Scenario 3: Enricher integration (unchanged behavior)

**Goal**: Verify that the `Enricher` still works correctly with the updated `Service`.

**Steps**:
1. Run the full `externalref` test suite:
   ```bash
   task test:unit ./pkg/sbom/externalref/...
   ```
2. Verify that enricher tests (parallel resolution, error aggregation, deduplication) all pass.

**Expected**: All enricher tests pass — they are timing-independent and only test behavior.

### Scenario 4: Backward compatibility — custom HTTP client

**Goal**: Verify that callers passing a custom `HTTPClient` still work.

**Steps**:
1. The test `"returns error on server error (without retry)"` in `service_test.go` passes a custom `HTTPClient` with 30 s timeout. This test must still pass.

**Expected**: Test passes — custom client override is preserved.

### Scenario 5: Full build

**Goal**: Verify the project builds cleanly.

**Steps**:
```bash
task build
```

**Expected**: Build succeeds with no errors.

## References

- [Data Model](data-model.md) — entity definitions and retry parameter table
- [Contracts](contracts/README.md) — public API contract documentation
- [Specification](spec.md) — full feature specification
- [Service source](../../pkg/sbom/externalref/service.go) — target file for changes