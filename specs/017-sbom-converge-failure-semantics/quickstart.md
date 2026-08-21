# Quickstart Validation: SBOM Converge Failure Semantics

**Feature**: 017-sbom-converge-failure-semantics

## Prerequisites

- Linux with Docker and kind (e2e environment pre-configured; see constitution Environment Configuration).
- A container registry reachable from the build (`--repo`), SBOM enabled in `werf.yaml` (`build.sbom.enable`).
- A controllable PURL resolver endpoint via `WERF_EXTERNAL_REFS_SERVER_URL` (unit/e2e tests use `httptest` mocks; manual runs can point at an unreachable address).

## Unit-level validation

```sh
task test:unit paths="./pkg/sbom/externalref/..."
task test:unit paths="./pkg/build/..."
```

Expected new coverage (see [data-model.md](./data-model.md) for entities):

- Failure classification: 404/4xx/empty-URL → content; timeout/conn-refused/429/5xx → infra.
- Breaker transitions: trips after threshold consecutive infra failures; success resets; content failures never count; tripped breaker fails `Allow()` immediately; concurrent recording is safe.
- Skip logic: image with failed base is skipped with root cause; transitive A→B→C reports A; aggregated report contains both failure kinds.
- Report on every exit path: happy, hard error, breaker trip.

## Scenario validation (e2e / manual)

### US1 — dependent image reports the real cause

1. Project with images `a` and `b` (`b` has `fromImage: a`); resolver mock fails one of `a`'s packages with 404.
2. Run build with SBOM enabled.
3. Expect: `b` reported as skipped with `a`'s enrichment error; aggregated report printed; **zero** occurrences of "rebuild it with SBOM generation enabled".

### US2 — unavailable resolver fails fast

1. Set `WERF_EXTERNAL_REFS_SERVER_URL` to an unreachable address; project with 5+ images.
2. Run build.
3. Expect: build fails after the breaker threshold (not after per-image retry budgets × image count); exactly one `PURL resolver unavailable at <addr>` error; accumulated report printed.

### US3 — log quality

1. Run a build with a failing resolve, GOST enabled on several images, and a final repo configured.
2. Inspect the log:
   - error text inside the failing image's `SBOM processing` block, next to FAILED;
   - GOST experimental warning appears exactly once;
   - `Copy SBOM artifacts into the final repo <address>` includes the address;
   - external-ref resolution has its own timed log section;
   - multiple-artifact-entries warning (if triggered) names the image and selected entry.

```sh
task test:e2e paths="./test/e2e/sbom/..." labelFilter="sbom"
```

## Regression gates

```sh
task format
task build
task lint
task test:unit
```
