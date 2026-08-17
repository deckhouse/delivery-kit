# Problem: SBOM converge error reporting

**Status**: backlog (not started)

**Discovered**: 2026-08-12, operator-helm build failure on werf 2.77.0-dk.2

## The bug

`convergeSbomByImagesSets` defers `ErrExternalRefEnrich` failures (stores them in
`purlErrors`, `return nil`) so a single flaky PURL resolve does not kill a long build
and the user gets one aggregated report at the end. The deferral has a side effect:
the SBOM of the failed image is never pushed. When that image has dependents in later
image sets (`fromImage`), the dependent hard-fails in `collectBaseImageSbom` with:

    the base image ... must have an SBOM artifact attached; to generate an SBOM for
    the base image, rebuild it with SBOM generation enabled: ... artifact not found

which (a) states a wrong cause — the base was built by this very run with SBOM
enabled, the real cause is a PURL resolver timeout — and (b) aborts the build before
the aggregated PURL report is ever printed. The aggregation contract only holds for
leaf images.

Observed log (operator-helm):

    ┌ image builder/golang: SBOM processing
    │ WARNING: resolve PURL failed, retrying...: resolve "pkg:nuget/C5@2.5.3":
    │   Client.Timeout exceeded
    └ image builder/golang: SBOM processing (50.24 seconds) FAILED
    ...
    Error: ... the base image ... must have an SBOM artifact attached ...

## Fix plan

1. `collectBaseImageSbom` / `GetImageBOM`: when the base SBOM is missing, consult
   `purlErrors` by the base image name and report the real cause:
   `SBOM for base image %q was not generated: <enrich error>`.
2. Guarantee the aggregated PURL report is printed on every exit path of
   `convergeSbomByImagesSets` (defer), not only on the happy path.
3. Optionally stricter: an image that failed enrich and has dependents fails the set
   immediately with the aggregated report.

## Logging improvements (same area)

1. **FAILED without a cause**: `image builder/alpine: SBOM processing (11.39s) FAILED`
   prints nothing about why — the error goes silently to the accumulator; warnings
   only appear from the retry callback. Print the error inside the image's log block
   before deferring it: FAILED must sit next to its cause.
2. **Misleading advice**: only suggest "rebuild it with SBOM generation enabled" when
   the base SBOM is absent AND its converge did not fail in this run.
3. **GOST warning spam**: `GOST SBOM integration is experimental...` is printed once
   per image (14 times per build). Print once per process.
4. **Context-free warning**: `WARNING: multiple artifact entries (imageName not
   specified, found 3 entries for digest ...)` floats between image blocks — say
   which image's lookup produced it, which image names the entries carry, and which
   one was picked.
5. **No final repo address**: `Copy SBOM artifacts into the final repo` does not name
   the repo (`pkg/build/sbom_step.go`, `PropagateArtifacts`) — add `%s` with the
   address; same for the cache repos message.
6. **Invisible retry time**: PURL retries add tens of seconds to the image block
   (scan 39.5s vs block 50.2s) with no sub-process — wrap external-ref resolution in
   its own `LogProcess` with a timer.

## Related (operational, not werf)

- The external-refs resolver timed out on `pkg:nuget/C5@2.5.3` — check the service.
- A golang builder image scan yields a nuget package — find out where syft picks it
  up from; it causes pointless resolver traffic. (Under investigation.)
