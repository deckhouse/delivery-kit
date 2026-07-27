# Research: Reduce PURL Resolver Retries Duration

## Research Questions

### 1. What are the default `cenkalti/backoff/v5` ExponentialBackOff parameters?

**Decision**: Use the library defaults for `InitialInterval`, `Multiplier`, and `MaxInterval` — no changes needed.

**Rationale**: The `backoff.NewExponentialBackOff()` defaults are:
- `InitialInterval`: 500 ms
- `Multiplier`: 1.5
- `MaxInterval`: 60 s
- `MaxElapsedTime`: 15 m (overridden by our explicit `WithMaxElapsedTime`)

These defaults are reasonable for retry-with-backoff against a network service. The spec requires preserving them (FR-002). Only `MaxElapsedTime` and the HTTP client timeout need to change.

**Alternatives considered**:
- Making all parameters configurable via `ServiceConfig` — not needed; the spec explicitly says to preserve the existing strategy.
- Using a custom backoff with different multiplier — no requirement for this.

### 2. How does the HTTP client timeout interact with the retry budget?

**Decision**: Lower HTTP client timeout from 30 s to 5 s.

**Rationale**: With the current 30 s timeout, a single slow request can consume the entire 30 s retry budget, leaving no opportunity for retries on transient errors. With the new 10 s retry budget, a 5 s timeout allows up to 2 retries before the budget is exhausted, improving resilience for transient failures.

**Alternatives considered**:
- Setting timeout to 10 s (same as retry budget) — would leave zero room for retries, defeating the purpose of having a retry mechanism.
- Making timeout configurable — not required; a single sensible default is sufficient.

### 3. Are there any callers of `NewService` that pass a custom `HTTPClient` or `Timeout`?

**Decision**: Two call sites exist:
1. `NewService(ServiceConfig{ServerURL: ts.URL})` in tests — uses default timeout (will pick up new default).
2. `NewService(ServiceConfig{ServerURL: serverURL})` in `patcher.go:NewExternalRefPatcher()` — uses default timeout (will pick up new default).
3. `NewService(ServiceConfig{ServerURL: ts.URL, HTTPClient: &http.Client{Timeout: 30 * time.Second}})` in `service_test.go` line 92 — explicitly passes a 30 s timeout client. This test (`"returns error on server error (without retry)"`) intentionally bypasses the default timeout to test behavior with a slow server. It passes a 2-second context deadline as the test's actual timeout mechanism. This test should remain as-is — it's testing the no-retry scenario, not the default timeout.

**Conclusion**: No callers need updating. The two production call sites use the default timeout, which will inherit the new 5 s value.

### 4. Which tests need updating?

**Decision**: Update `service_test.go` to verify the new retry window and timeout. The enricher tests are timing-independent (they use mock servers that respond instantly) and need no changes.

**Rationale**: The existing tests that measure timing behavior use the default `NewService` which will pick up the new 5 s timeout. The test "returns error on server error (without retry)" explicitly passes a 30 s client and a 2-second context deadline — this test checks that a server error (500) is retried, and relies on the 2-second context deadline to eventually give up. This test's behavior is unchanged by our modification.

## Consolidated Findings

| Aspect | Decision | Impact |
|--------|----------|--------|
| `MaxElapsedTime` | 10 s (was 30 s) | Main retry budget reduction |
| HTTP client timeout | 5 s (was 30 s) | Prevents slow requests from eating retry budget |
| Backoff parameters | Unchanged (library defaults) | Preserves existing retry strategy |
| `ServiceConfig` API | Unchanged | No breaking changes |
| Test changes | Update `service_test.go` | Verify new timing constants |