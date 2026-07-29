# Data Model: Tag Mutex Manager

## Entities

### `tagMutexKey`

A string key derived from the repository and parent digest, used to identify the mutex for a specific fallback tag.

| Field | Derivation | Example |
|-------|-----------|---------|
| `key` | `repo + "/" + FallbackTag(parentDigest)` | `"registry.example.com/app sha256-abc123def456"` |

### `fallbackTagMutexes` (package-level state)

A pair of variables providing per-tag serialization for concurrent `Attach()` calls.

| Variable | Type | Purpose |
|----------|------|---------|
| `tagMutexes` | `map[string]*sync.Mutex` | Map of tag key → mutex, lazy-initialized |
| `tagMutexGuard` | `sync.Mutex` | Guard protecting concurrent access to `tagMutexes` |

### `maxRetries` (removed)

Package-level variable `var maxRetries = 3` — **removed**, replaced by time-based budget.

## State Transitions

### `Attach()` call flow (with fix)

```
Enter Attach()
  │
  ├─ key = repo + "/" + FallbackTag(parentDigest)
  ├─ m = getTagMutex(key)     ← new: acquire per-tag mutex
  ├─ m.Lock()
  │
  ├─ backoff.Retry(...)        ← existing CAS loop
  │    ├─ pullFallbackIndex()
  │    ├─ updateFallbackIndex()
  │    ├─ pushFallbackIndex()
  │    └─ read-after-write digest verification
  │
  └─ m.Unlock()               ← new: release per-tag mutex
```

## Validation Rules

| Rule | Enforcement |
|------|------------|
| Mutex must be acquired before entering CAS loop | Code structure — acquire at top of `Attach`, defer unlock before returning |
| Mutex must be released on all exit paths | Use `defer m.Unlock()` immediately after `Lock()` |
| Retry budget must be bounded | `backoff.WithMaxElapsedTime(30 * time.Second)` — automatically bounded |
| Tag key must be deterministic | Same `(repo, parentDigest)` must produce same key |

## Error Handling Matrix

| Scenario | Behavior |
|----------|----------|
| Registry returns 404 on initial read | Returns `empty.Index` (unchanged) |
| Registry returns non-404 error | Returns error to caller (unchanged) |
| CAS verification fails, retries succeed | Succeeds with correct data |
| CAS verification fails, budget exhausted | Returns error with descriptive message |
| Concurrent goroutine waiting on mutex | Blocks until first completes, then reads fresh data |