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

## 2. CAS Retry Budget

### Decision

Replace `maxRetries = 3` (package-level variable) and `backoff.WithMaxTries(uint(maxRetries))` with `backoff.WithMaxElapsedTime(30 * time.Second)`.

### Rationale

- The requirement is 30s maximum convergence per the spec.
- `backoff.WithMaxElapsedTime` is already used in the codebase: `pkg/sbom/externalref/service.go`, `pkg/docker_registry/auth/auth.go`.
- With 500ms base interval and 2x multiplier, 30 seconds allows ~5-6 retries:
  - Try 1: 0s (500ms wait → 500ms)
  - Try 2: 0.5s (1s wait → 1.5s)
  - Try 3: 1.5s (2s wait → 3.5s)
  - Try 4: 3.5s (4s wait → 7.5s)
  - Try 5: 7.5s (8s wait → 15.5s)
  - Try 6: 15.5s (16s wait → 31.5s → capped at 30s)
- The per-tag mutex makes the CAS loop a secondary defense (for cross-process/registry-staleness), so 6 tries is more than sufficient.
- Remove the `maxRetries` variable entirely — the timeout is self-documenting.

### Alternatives Considered

- **Increase `maxRetries` to a higher number**: Less precise than a time budget, and doesn't cap worst-case latency.
- **Custom backoff config**: `backoff.WithMaxElapsedTime` does exactly what we need with no custom code.

---

## 3. Testing Concurrent Registry Writes

### Decision

Add a Ginkgo integration test in `attach_integration_test.go` using `sync.WaitGroup` with goroutines.

### Rationale

- The existing in-memory registry (`httptest.NewServer(registry.New())`) is thread-safe — it serializes requests internally.
- `sync.WaitGroup` is the standard Go pattern for waiting on goroutines.
- The test must:
  1. Push SBOMs for 3 different image names (`app-a`, `app-b`, `app-c`) to the same parent digest concurrently.
  2. Verify all 3 succeed (no errors).
  3. Verify all 3 annotations exist in the final fallback index.

### Key Pattern

```go
It("should retain all annotations under concurrent push", func(ctx SpecContext) {
    var wg sync.WaitGroup
    errs := make([]error, 3)
    names := []string{"app-a", "app-b", "app-c"}

    for i, name := range names {
        wg.Add(1)
        go func(i int, name string) {
            defer wg.Done()
            errs[i] = attachWithPayload(ctx, []byte(`{"img":"`+name+`"}`), name)
        }(i, name)
    }
    wg.Wait()

    for i, name := range names {
        Expect(errs[i]).To(Succeed(), "Attach for %s should succeed", name)
    }

    im := pullIndex(ctx)
    Expect(werfEntries(im)).To(HaveLen(3))
})
```

### Alternatives Considered

- **`gomega/gleak` goroutine leak detection**: Valuable but out of scope for this fix.
- **Table-driven concurrent test**: Possible with Ginkgo `DescribeTable` but awkward — concurrent goroutines don't fit table entries cleanly.