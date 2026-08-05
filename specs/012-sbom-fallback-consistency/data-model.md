# Data Model: Tag Mutex Manager

## Entities

### `tagMutexKey`

A string key derived from the repository and parent digest, used to identify the mutex for a specific fallback tag.

| Field | Derivation | Example |
|-------|-----------|---------|
| `key` | `repo + "/" + FallbackTag(parentDigest)` | `"registry.example.com/app/sha256-abc123def456"` |

### `fallbackTagMutexes` (package-level state)

A pair of variables providing per-tag serialization for concurrent `Attach()` calls.

| Variable | Type | Purpose |
|----------|------|---------|
| `tagMutexes` | `map[string]*sync.Mutex` | Map of tag key → mutex, lazy-initialized |
| `tagMutexGuard` | `sync.Mutex` | Guard protecting concurrent access to `tagMutexes` |

### `maxRetries` (removed)

Package-level variable `var maxRetries = 3` — **removed**, replaced by `backoff.WithMaxElapsedTime(30 * time.Second)`.

### `getTagMutex` (new)

Package-level function returning the per-tag mutex, following `Conveyor.GetStageDigestMutex` and `GitMapping.getMutex` conventions.

## State Transitions

### `Attach()` call flow (with corrected fix)

```
Enter Attach(ctx, repo, parentDigest, artifactDesc, artifactType, imageName, opts...)
  │
  ├─ key = repo + "/" + FallbackTag(parentDigest)
  ├─ m = getTagMutex(key)
  │
  ├─ m.Lock()                    ← serialize werf writers to this tag
  │
  │  // ---- read-modify-write ----
  │  ├─ (1) pullFallbackIndex()          // read current index from registry
  │  ├─ (2) updateFallbackIndex()        // append/replace descriptor
  │  ├─ (3) pushFallbackIndex()          // write updated index to registry
  │
  │  // ---- consistency wait ----
  │  └─ (4) backoff.Retry(ctx, ...)
  │       └─  pullFallbackIndex()
  │            └─  digest matches what we wrote? → done
  │                └─  digest mismatch? → retry (up to 30s budget)
  │
  └─ m.Unlock()                  ← release so next writer can proceed
```

## Validation Rules

| Rule | Enforcement |
|------|------------|
| Mutex must be acquired before RMW cycle | Code structure — `Lock()` at top of `Attach`, `defer Unlock()` |
| Mutex must be released on ALL exit paths (success or error) | `defer m.Unlock()` immediately after `Lock()` |
| Consistency wait must have bounded budget | `backoff.WithMaxElapsedTime(30 * time.Second)` |
| Tag key must be deterministic | Same `(repo, parentDigest)` → same key always |
| Digest mismatch MUST return descriptive error | `return false, fmt.Errorf("consistency check failed: digest mismatch")` — NOT `return false, nil`, otherwise the last error is lost when budget exhausted |
| Retry loop must use `SpecContext`, never `context.Background()` | Ginkgo convention — all test entry points receive `ctx SpecContext` |

## Error Handling Matrix

| Scenario | Behavior |
|----------|----------|
| Registry returns 404 on initial read | Returns `empty.Index` → updateFallbackIndex creates index with first descriptor |
| Registry returns non-404 error (read or write) | Returns error to caller — lock released on all paths |
| Consistency wait succeeds within budget | Returns nil — annotations confirmed in registry |
| Consistency wait budget exhausted | Returns descriptive error `"consistency check failed: digest mismatch"` — not a generic nil, critical for debugging |
| Concurrent goroutine waiting on same tag | Blocks on `m.Lock()` — proceeds after first completes with fresh data |

## Test Patterns (data model for tests)

### Mutex serialization unit test

- **Setup**: Create two goroutines calling `getTagMutex("same-key")`
- **Assert**: First locks, second blocks until first unlocks

### Concurrent getTagMutex unit test

- **Setup**: 100 goroutines cycling through 5 keys calling `getTagMutex()`
- **Assert**: No data races (run with `-race`), all complete

### Concurrent Attach integration test

- **Setup**: 3 goroutines calling `Attach()` for names `app-a`, `app-b`, `app-c` to same parent digest
- **Assert**: All 3 return success, all 3 annotations present in final index