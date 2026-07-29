# Validation Guide: SBOM Fallback Consistency

## Prerequisites

- `task build` passes
- `task test:unit` passes on the existing codebase (baseline)
- Go with race detector (`-race` flag) — needed for concurrent test validation

## Validation Scenarios

### 1. Unit Tests — `fallback_test.go`

**What it validates**: The per-tag mutex correctly serializes concurrent calls.

```bash
task test:unit paths="./pkg/oci/artifact/..." -- -run "TestArtifact" -race
```

**Expected outcome**: All tests pass, race detector reports no data races.

### 2. Concurrent Push Integration Test

**What it validates**: Three concurrent `Attach()` calls for different image names
(`app-a`, `app-b`, `app-c`) to the same parent digest all succeed, and all three
annotations survive in the final fallback index.

```bash
task test:unit paths="./pkg/oci/artifact/..." -- -run "TestArtifact" -race
```

**Expected outcome**: All entries present in the index manifest, zero annotation loss,
zero data races detected.

### 3. Read Path Regression Test

**What it validates**: `GetAttached` still works identically:

- Returns correct descriptor for known annotations
- Returns `(empty, false)` for non-existing index
- No performance regression per SC-004

```bash
task test:unit paths="./pkg/oci/artifact/..." -- -run "TestArtifact"
```

**Expected outcome**: All existing `GetAttached` test cases pass with identical results.

### 4. Full Unit Test Suite

```bash
task test:unit paths="./pkg/oci/artifact/..."
```

**Expected outcome**: All tests pass.

### 5. Build Check

```bash
task build
```

**Expected outcome**: Binary compiles without errors.

## Manual Verification (Optional)

If an in-memory registry test pass seems insufficient:

1. Start an OCI-compatible registry (e.g., `docker run -p 5000:5000 registry:2`)
2. Build an image and push it
3. Attach SBOMs for multiple image names pointing to the same parent digest
4. Verify all annotations are present using `PullFallbackIndex`

## Edge Cases to Verify

| Scenario | How to Test | Expected |
|----------|-------------|----------|
| Single-image push (no concurrency) | Run existing `attach_integration_test.go` tests | All pass, identical to pre-fix behavior |
| Cross-process concurrency | Not tested (out of scope) | CAS loop handles via retry |
| Registry returns stale data | Simulation via mock/controlled retry | Eventual convergence within 30s |
| Registry never converges | Use `backoff.WithMaxElapsedTime(1*time.Second)` in unit test | Error returned within timeout |