# Research Findings: SBOM Fallback Annotation Loss Fix

## 1. Per-Key Mutex Pattern

### Decision

Use `map[string]*sync.Mutex` protected by a guard `sync.Mutex` — exactly the pattern already established in the codebase.

### Rationale

The codebase has two canonical examples of the same pattern:

- `Conveyor.stageDigestMutex` / `GetStageDigestMutex()` in `pkg/build/conveyor.go`
- `GitMapping.mutexes` / `getMutex()` in `pkg/build/stage/git_mapping.go`

Both use:

```go
var (
    mutexes map[string]*sync.Mutex
    guard   sync.Mutex
)

func getMutex(key string) *sync.Mutex {
    guard.Lock()
    defer guard.Unlock()

    if mutexes == nil {
        mutexes = make(map[string]*sync.Mutex)
    }
    m, ok := mutexes[key]
    if !ok {
        m = &sync.Mutex{}
        mutexes[key] = m
    }
    return m
}
```

**Why not `sync.Map`**: `sync.Map` is optimized for read-heavy, write-once patterns — not a good fit for a small, contended set of keys. The guard-mutex pattern is simpler, already established, and the codebase's own convention.

**Lock lifecycle**: Keep forever. Memory footprint is negligible (≈8 bytes per key). Cleanup introduces race risks without benefit.

### Alternatives Considered

- **`sync.Map` storing `*sync.Mutex`**: Adds complexity, no benefit for this use case.
- **Single global `sync.Mutex`**: Too coarse — would serialize all `Attach` calls across all repositories, defeating parallelism for unrelated images.
- **Channel-based semaphore per key**: Overengineered for what is fundamentally a mutex.

---

## 2. Corrected Algorithm: Mutex covers RMW + consistency wait

### Decision

The per-tag mutex must serialize the **entire** operation, including the consistency wait. The lock scope is:

```
Lock
  ├─ (1) pullFallbackIndex()     // read current index
  ├─ (2) updateFallbackIndex()   // append/replace descriptor
  ├─ (3) pushFallbackIndex()     // write updated index
  └─ (4) backoff.Retry(...)      // wait-for-tag: read + digest verify
       ├─ pullFallbackIndex()
       └─ digest match? → succeed / retry
Unlock
```

### Rationale

- **Mutex serializes werf writers**: Only one goroutine at a time can go through RMW + consistency verification for a given tag. This eliminates CAS conflicts entirely within a single process.
- **Retry is for registry eventual consistency only**: After our write lands, the registry may serve stale data. The retry loop repeatedly reads until the digest matches what we wrote.
- **Why hold the lock during consistency wait**: If we released the lock right after writing, another goroutine could start its RMW before our write became visible. That goroutine would read stale data, produce an index that omits our entry (or duplicates it), and write — corrupting the index. Holding the lock ensures no writer starts until the previous writer's data is confirmed visible.

### Current vs. corrected code

**Current (`fallback.go` lines 50-84)** — retry wraps the entire RMW:

```go
_, err := backoff.Retry(ctx, func() (bool, error) {
    current, err := pullFallbackIndex(ctx, repo, parentDigest, opts...)
    next := updateFallbackIndex(current, artifactDesc, artifactType, imageName)
    pushFallbackIndex(ctx, repo, parentDigest, next, opts...)

    verified, err := pullFallbackIndex(ctx, repo, parentDigest, opts...)  // CAS check
    if verifiedDigest != nextDigest {
        return false, fmt.Errorf("CAS mismatch: concurrent write detected")
    }
    return true, nil
}, ...)
```

**Corrected** — lock first, retry is for consistency wait only:

```go
m := getTagMutex(repo + "/" + FallbackTag(parentDigest))
m.Lock()
defer m.Unlock()

current, err := pullFallbackIndex(ctx, repo, parentDigest, opts...)
next := updateFallbackIndex(current, artifactDesc, artifactType, imageName)
if err := pushFallbackIndex(ctx, repo, parentDigest, next, opts...); err != nil {
    return err
}

_, err = backoff.Retry(ctx, func() (bool, error) {
    verified, err := pullFallbackIndex(ctx, repo, parentDigest, opts...)
    if err != nil {
        return false, err  // permanent error → stop
    }

    verifiedDigest, err := verified.Digest()
    if err != nil {
        return false, fmt.Errorf("get verified index digest: %w", err)
    }
    nextDigest, err := next.Digest()
    if err != nil {
        return false, fmt.Errorf("get next index digest: %w", err)
    }

    if verifiedDigest != nextDigest {
        return false, fmt.Errorf("consistency check failed: digest mismatch")  // stale read → retry
    }

    return true, nil
},
    backoff.WithBackOff(eb),
    backoff.WithMaxElapsedTime(30*time.Second),
)
return err
```

> **Important**: `return false, nil` would lose the error context — `backoff.Retry`
> preserves the last error returned by the operation. If the budget is exhausted,
> the caller receives `"consistency check failed: digest mismatch"` instead of
> a generic `nil` — critical for debugging.

### Retry Budget

Replace `maxRetries = 3` with `backoff.WithMaxElapsedTime(30 * time.Second)`:

- Already used in the codebase: `pkg/sbom/externalref/service.go`, `pkg/docker_registry/auth/auth.go`.
- With 500ms base interval and 2x multiplier: ~5-6 retries within the 30s window.
- Remove the `maxRetries` package variable entirely.

---

## 3. Test Patterns: `samber/lo/parallel` for concurrency

### Decision

Use `samber/lo/parallel` for concurrent test patterns (`parallel.ForEach`, `parallel.Times`)
and standard Go `for` loops for non-concurrent code (assertions).
Always use Ginkgo `SpecContext` or `Context` — never `context.Background()`.

### Rule: concurrent → `parallel`, assertions → standard loop

- For spawning goroutines: prefer `samber/lo/parallel` over manual `go func() + sync.WaitGroup`.
- For checking results or assertions: use standard `for i := range` or `for _, item := range` —
  no need for `lo` here.

### Concurrent `getTagMutex` test (replaces `Untitled:42-51`)

```go
It("handles concurrent getTagMutex calls without race", func(ctx SpecContext) {
    keys := []string{"a", "b", "c", "d", "e"}

    parallel.Times(100, func(i int) struct{} {
        _ = getTagMutex(keys[i%len(keys)])
        return struct{}{}
    })
})
```

`parallel.Times` spawns a goroutine for each iteration and waits for all to complete.
No manual `sync.WaitGroup` needed.

### Concurrent `Attach` test (replaces `Untitled:124-139`)

```go
It("retains all annotations under concurrent push", func(ctx SpecContext) {
    names := []string{"app-a", "app-b", "app-c"}

    parallel.ForEach(names, func(name string, i int) {
        store := NewOCIStore(repo, name, remoteOpts...)
        payload := lo.Must(json.Marshal(map[string]string{"img": name}))
        Expect(store.Attach(ctx, parentDigest, artifactType, payload, "", "")).To(Succeed())
    })

    im := pullIndex(ctx)
    Expect(werfEntries(im)).To(HaveLen(3))
})
```

`parallel.ForEach` spawns a goroutine per item. `Expect().To(Succeed())` in each
goroutine fails the test immediately if Attach returns an error — no custom
`attachE` helper needed.

Assertions use a standard `for` loop — clearer than `lo.ForEach` for this
purpose.

### Mutex blocks other writers test (replaces `Untitled:22-28`)

```go
It("prevents concurrent writer from proceeding until lock released", func(ctx SpecContext) {
    m1 := getTagMutex("test-key")
    m2 := getTagMutex("test-key")
    m1.Lock()

    locked := make(chan struct{})
    go func() {
        m2.Lock()
        close(locked)
        m2.Unlock()
    }()

    Consistently(locked, 100*time.Millisecond).ShouldNot(BeClosed())
    m1.Unlock()
    Eventually(locked, time.Second).Should(BeClosed())
})
```

This is a blocking test (not true parallelism) — single goroutine with channel
communication. `lo`/`parallel` would add no value here; standard Go is appropriate.

## 4. E2E Testing

### Decision

Use the existing e2e tests in `test/e2e/sbom/` with a dedicated Ginkgo label `"annotation-consistency"`
for targeted execution. The label MUST be placed on `Describe` / `DescribeTable` level, not on
individual `Entry` calls.

1. **Regression test** (`regressions_test.go`, from `specs/010-sbom-fallback-annotation-loss`):
   builds two images (`frontend`, `backend`) sharing the same digest and asserts
   `io.werf.image-name` annotations on the fallback index descriptors.
   → Add `"annotation-consistency"` to its existing `Label("e2e", "sbom", "regression", "simple")`.

2. **Multi-image lifecycle test** (`lifecycle_test.go`): builds two images, merges their
   SBOMs into a product SBOM, and validates component/license/hash assertions — exercises
   the full SBOM pipeline through the fallback index.
   → Add `"annotation-consistency"` to the `DescribeTable` label (multi-image DescribeTable),
      not to the outer `Describe` (which covers single-image tests too).

### Run requirement

Because the bug is stochastic (race condition), the fix must be validated by running the
e2e tests at least **3 times** consecutively. All 3 runs must pass.

### Rationale

- The existing labels (`"regression"`, `"lifecycle"`) are too broad — `labelFilter="e2e && sbom"`
  would also match single-image lifecycle tests and other sbom suites, adding unnecessary run time.
- Adding `"annotation-consistency"` to both relevant test cases enables a precise filter:
  ```
  labelFilter="annotation-consistency"
  ```
- This runs exactly the 2 test suites (6 entries: 2 regression + 4 multi-image) and nothing else.

### Alternatives Considered

- **New e2e test in `test/e2e/attest/`**: Unnecessary duplication — the regression test in `test/e2e/sbom/` already covers the scenario with an isolated fixture.
- **Unit test only**: Unit tests with in-memory registry can verify in-process concurrency, but e2e is needed to validate the full werf SBOM pipeline with concurrent multi-image builds.