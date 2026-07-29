# Validation Guide: SBOM Fallback Consistency

## Prerequisites

- `task build` passes
- `task test:unit` passes on the existing codebase (baseline)
- Go with race detector (`-race` flag) — needed for concurrent test validation

## Validation Scenarios

### 1. Mutex Serialization Unit Tests — `fallback_test.go`

**What it validates**: The per-tag mutex correctly serializes concurrent calls, the blocking behavior, and concurrent `getTagMutex` access without races.

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

```bash
task test:unit paths="./pkg/oci/artifact/..." -- -run "TestArtifact"
```

**Expected outcome**: All existing `GetAttached` test cases pass with identical results.

### 4. Full Unit Test Suite

```bash
task test:unit
```

**Expected outcome**: All tests pass.

### 5. Build Check

```bash
task build
```

**Expected outcome**: Binary compiles without errors.

### 6. E2E Tests (mandatory)

Two existing e2e test suites validate the fix end-to-end. Both get a dedicated Ginkgo label
`"annotation-consistency"` on the `Describe` / `DescribeTable` level for precise targeting.

**Regression test** — from `specs/010-sbom-fallback-annotation-loss`, builds two images
(`frontend`, `backend`) sharing the same parent digest and asserts that
`io.werf.image-name` annotations survive in the fallback index descriptors.

**Multi-image lifecycle test** — builds two images, merges their SBOMs into a product
SBOM, and validates component/license/hash assertions. Annotation loss would cause
"artifact not found" errors during merge.

```bash
# Run 3 times because the race condition is stochastic
for i in 1 2 3; do
    echo "--- Run $i/3 ---"
    task test:e2e paths="./test/e2e/sbom/regressions_test.go,./test/e2e/sbom/lifecycle_test.go" labelFilter="annotation-consistency"
done
```

**Expected outcome**: All 3 runs pass.

**Note**: E2E tests require Linux with Docker and kind. Run `task test:setup:environment`
first if the environment hasn't been provisioned.

## Edge Cases to Verify

| Scenario | How to Test | Expected |
|----------|-------------|----------|
| Single-image push (no concurrency) | Run existing `attach_integration_test.go` tests | All pass, identical to pre-fix behavior |
| Cross-process concurrency | Not tested in isolation (out of scope) | Consistency-wait loop handles via retry |
| Registry returns stale data | In-memory registry + controlled timing | Eventual convergence within 30s |
| Registry never converges | `backoff.WithMaxElapsedTime(1*time.Second)` in unit test | Error returned within timeout |