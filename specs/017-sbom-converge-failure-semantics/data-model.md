# Data Model: SBOM Converge Failure Semantics

**Feature**: 017-sbom-converge-failure-semantics

## Entities

### FailureClass (pkg/sbom/externalref)

The classification of a single resolution failure. String-typed enum per code style (no `iota`).

| Value | Meaning | Sources |
|-------|---------|---------|
| `FailureClassContent` | Resolver answered authoritatively; retrying is pointless and the breaker must not count it | HTTP 404 and other non-429 4xx, empty URL in response, unparseable response |
| `FailureClassInfra` | Resolver unreachable or unhealthy; counts toward the breaker | transport errors (timeout, connection refused), HTTP 429, HTTP 5xx |

Carried by a typed error (`ClassifiedError{Class, err}` or equivalent) produced inside `doResolve`, wrapping the underlying error so `errors.Is`/`errors.As` chains keep working. `backoff.Permanent` wrapping is preserved for the retry loop; classification is orthogonal to retryability (they coincide today but are stated separately).

### ResolverBreaker (pkg/sbom/externalref)

Process-wide (one per build) availability state of the shared resolver endpoint.

| Field | Type | Notes |
|-------|------|-------|
| `endpoint` | `string` | resolver server URL, for the terminal error message |
| `consecutiveInfra` | counter (mutex-guarded) | incremented on infra failure, reset to 0 on any success or content failure |
| `lastInfraErr` | `error` | last observed infra error, embedded in the terminal error |
| `tripped` | `bool` | latched; never resets within a build |

Behavior:
- `Allow() error` — returns `ErrResolverUnavailable`-wrapped error when tripped; checked before starting a resolve (before the retry loop).
- `Record(class FailureClass, err error)` / `RecordSuccess()` — state transitions.
- Threshold: fixed constant `resolverBreakerThreshold = 5` (FR-015; see research R2).
- Concurrency: accessed from up to (parallel images × 10 enricher goroutines); all transitions under one mutex.

State transitions:

```
closed --[infra failure, consecutiveInfra+1 == threshold]--> tripped (terminal)
closed --[success | content failure]--> closed (counter reset on success; content does not touch counter)
tripped --[any call]--> tripped (Allow() fails fast)
```

### Sentinel error: ErrResolverUnavailable (pkg/sbom/externalref)

`var ErrResolverUnavailable = errors.New("PURL resolver unavailable")`. Wrapped with endpoint and last infra error:
`PURL resolver unavailable at <endpoint>: <last infra error>`. Detected in the build phase via `errors.Is` to short-circuit remaining work.

### Enrichment failure record (pkg/build, existing — extended)

The existing `sync.Map purlErrors` in `convergeSbomByImagesSets`, keyed by werf image name. Value becomes a small struct instead of the bare details string:

| Field | Type | Notes |
|-------|------|-------|
| `details` | `string` | component-level lines (existing `ComponentError.ComponentDetails()`) — empty for skip records |
| `rootImage` | `string` | for skip records: the image whose enrichment originally failed; equals own name for direct failures |
| `rootCause` | `string` | for skip records: the root image's enrichment error summary |

An image name present in the map means "SBOM not generated in this run" for dependency purposes (FR-005).

### Skip record (pkg/build)

A `purlErrors` entry whose `rootImage != own name`. Created when an image's base (by `GetBaseImageName()`) is found in the map before converge starts (FR-006). Transitive chains resolve automatically: the skip record copies `rootImage`/`rootCause` from the base's entry, so C skipping over B reports A (edge case in spec).

## Relationships

```
Service.doResolve ──produces──> ClassifiedError(FailureClass)
Service.Resolve   ──consults/updates──> ResolverBreaker ──trips──> ErrResolverUnavailable
Enricher          ──aggregates──> ComponentError (existing)
Patcher.Apply     ──wraps──> ErrExternalRefEnrich (existing)
convergeSbomByImagesSets ──records──> purlErrors[name] = failure record | skip record
convergeSbomByImagesSets ──defer──> aggregated report (all exit paths)
collectBaseImageSbom ──gates advice on──> purlErrors membership (FR-008)
```

## Validation rules

- A skip record MUST reference a root image that has a direct failure record (invariant: root of every skip chain is a direct failure).
- The breaker MUST never trip on content failures (FR-001/FR-003; acceptance scenario US2-3).
- `purlErrors` keys are werf image names — the same namespace as `GetBaseImageName()` for in-project bases (verified, research R4).
- The aggregated report includes both direct failures (component lines) and skip records (`skipped: ...` line) under the existing hierarchical format (research R8).
