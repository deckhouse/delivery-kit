# Research: SBOM Converge Failure Semantics

**Feature**: 017-sbom-converge-failure-semantics
**Date**: 2026-08-17

## R1. Where error classification already exists

**Decision**: Reuse the retryability decision tree in `pkg/sbom/externalref/service.go` `doResolve()` (lines 74–109) as the source of the content/infra classification, surfacing it as a typed error instead of only a `backoff.Permanent` wrapper.

**Rationale**: The code already distinguishes exactly the classes the spec needs:
- HTTP 429 / 5xx → returned bare (retryable) — infrastructure;
- transport errors (`httpClient.Do` failure: timeout, connection refused) → returned bare — infrastructure;
- HTTP 404 / other 4xx, empty URL, parse errors → `backoff.Permanent(...)` — content.

The `backoff.Permanent` marker is consumed by `backoff.Retry` and is not observable by callers of `Service.Resolve`, so the classification must be carried on a dedicated error type that survives the retry loop.

**Alternatives considered**:
- Inspecting error strings / status codes at the enricher level — brittle, duplicates the decision tree.
- A separate classifier function applied post-hoc — the information (status code, transport error) is only reliably available inside `doResolve`.

## R2. Circuit breaker placement

**Decision**: A small process-wide breaker owned by `pkg/sbom/externalref`, checked and updated inside `Service.Resolve`. `NewExternalRefPatcher` today constructs a fresh `Service` per platform image (`build_phase.go:365`); rather than restructuring patcher lifecycle, the breaker state is shared explicitly (constructed once in `convergeSbomByImagesSets` and passed down through `NewExternalRefPatcher` → `NewService`).

**Rationale**:
- The breaker models the health of the single shared resolver endpoint; per-`Service` state would never trip because each image gets its own instance.
- Passing the breaker explicitly (rather than a package-level global) keeps it testable and honors the constitution's minimal-state preference; the build phase owns its lifetime (one breaker per build).
- Checking inside `Resolve` (before `backoff.Retry`) means a tripped breaker skips the whole retry budget instantly, which is exactly the wasted time the spec targets.

**Alternatives considered**:
- Package-level singleton with `sync.Once` — hidden global state, hard to reset between tests and between builds in the same process (werf can run converge more than once per process in tests).
- Breaker at the enricher level — enricher parallelism (errgroup, limit 10) means component-level accounting still ends up in shared state; `Service` is the natural chokepoint since every resolution passes through it.
- Breaker at `convergeSbomByImagesSets` level only — too coarse: it could stop scheduling images but not stop in-flight per-component retries inside a running image.

**Threshold**: consecutive infrastructure failures reset by any success. Default **5** (single digits per spec assumption; large enough to survive one flaky blip under parallelism 10, small enough to trip within seconds of a real outage). Fixed constant, no configuration (FR-015).

**Concurrency note**: counter must be atomic/mutex-guarded — enricher resolves up to 10 components in parallel and the build phase runs multiple images in parallel.

## R3. How the breaker failure surfaces

**Decision**: When tripped, `Service.Resolve` returns a sentinel-wrapped error (`ErrResolverUnavailable`) naming the endpoint and the last infrastructure error. The enricher already aggregates component errors into `ComponentError`; the patcher already wraps with `ErrExternalRefEnrich`. In `convergeSbomByImagesSets`, a worker error that `errors.Is` `ErrResolverUnavailable` stops the set (hard error path), and the deferred aggregated report still prints (R5).

**Rationale**: Reuses the existing error propagation chain; only the terminal classification at the build phase changes. One resolver-unavailable error is reported once (SC-004) because the first worker to observe the trip carries it out; other workers' identical errors are subsumed (they also fail fast, but the build phase reports the terminal error once).

## R4. Recording enrichment failures for dependency skipping

**Decision**: Extend the existing `sync.Map purlErrors` (`build_phase.go:266`, keyed by werf image name) to be the record of "SBOM not generated in this run". Before converging an image, look up its base werf image name (`img.GetBaseImageName()` is non-empty exactly when the base is a werf image from an earlier set) in that map; on hit, skip the image and store a skip record pointing at the root cause.

**Rationale**:
- The map is already keyed by werf image name, which is the same namespace `GetBaseImageName()` returns for in-project bases — verified in `collectBaseImageSbom` (`build_phase.go:1711`) where `GetImageBOM(ctx, img.GetBaseImageName(), ...)` is called.
- Storing the skip record under the *skipped* image's own name makes transitive skipping (A→B→C) automatic: when C looks up B, it finds B's skip record and reuses the root cause.
- Multiplatform: `purlErrors` is keyed by image name (not name+platform), and `convergeImageSbom` fails the whole name on the first failing platform — matching the spec assumption for free.

**Alternatives considered**:
- A separate `failedImages` set — duplicate bookkeeping over the same key space; the map value (component details vs skip record) can carry the distinction.

## R5. Guaranteeing the aggregated report on every exit path

**Decision**: Hoist report emission into a `defer` in `convergeSbomByImagesSets`. On the happy path, behavior is unchanged (aggregated error returned as today). On a hard-error path, the aggregated report is *logged* (via logboek) before the hard error propagates, and the hard error remains the terminal error.

**Rationale**: `buildAggregatedPurlError` currently only runs after all sets complete (`build_phase.go:305`); any `return err` at line 301 loses the report. Returning `errors.Join(hardErr, aggErr)` was considered but rejected: callers up the stack (and users of `errors.Is`) expect the hard error's identity to dominate, and the report is human-facing output, not a programmatic error — logging it keeps the error chain clean.

## R6. Logging fixes — exact sites

All sites confirmed by code inspection:

| # | Fix | Site |
|---|-----|------|
| 1 | Print deferred enrich error inside the image's log block | The `LogProcess("image %s: SBOM processing")` block is `sbom_step.go:86`; the deferred classification happens in `convergeSbomByImagesSets` (`build_phase.go:290`). Print the error via `logboek` inside the worker right where it is deferred — the worker is still inside the image's block context. |
| 2 | Misleading advice only when base not built this run | `baseSbomMissingError` (`sbom_step.go:221–223`); gate at the caller `collectBaseImageSbom` (`build_phase.go:1711–1717`) which knows the run context. With the skip logic (R4) this path becomes unreachable for in-run bases; the message stays for genuinely foreign bases. |
| 3 | GOST warning once per build | `prepareGostComponents` (`sbom_step.go:246`) — guard with a once-flag owned by the `sbomStep` instance (a package-level `sync.Once` would be unresettable between tests). |
| 4 | Context in "multiple artifact entries" warning | `GetAttached` (`pkg/oci/artifact/fallback.go:247`) — has `parentDigest` and `matches` (each carrying image-name annotations) in scope; caller passes `imageName` context. |
| 5 | Repo address in copy messages | `PropagateArtifacts` (`sbom_step.go:174` final repo, `:185` cache) — final repo address available from `finalStageDesc`/step fields; cache message already prints `cache.String()`, only the final-repo message lacks the address. |
| 6 | Timer around external-ref resolution | Patcher loop `sbom_step.go:121–129` applies patchers uniformly. Wrap each patcher `Apply` in a named `LogProcess` (patchers gain a `Name()` or the external-ref patcher alone is special-cased); simplest compliant option: wrap only the external-ref patcher via a type check at the call site, keeping the patcher interface unchanged. |

## R7. Retry policy interaction (spec 011)

**Decision**: No change to per-request retry policy (`backoff.NewExponentialBackOff`, `MaxElapsedTime` 10s, `service.go:60–71`). The breaker sits above it: a tripped breaker short-circuits before `backoff.Retry` starts; an in-flight retry loop finishes its current budget.

**Rationale**: Spec assumption; also avoids re-opening `011-reduce-purl-retries-duration` decisions. In-flight loops finishing their budget bounds the worst case at (parallelism × one retry budget), still independent of total image count.

## R8. Aggregated report format extension

**Decision**: Keep the hierarchical format from `wiki/pages/error-aggregation-strategy.md`; skipped images appear as image-level entries whose detail line is `skipped: SBOM for base image "<root>" was not generated: <root cause>` instead of component lines.

**Rationale**: Consumers (humans, CI logs) keep one report shape; the summary line "N of M images failed" naturally counts skipped images in N.
