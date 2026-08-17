# Contracts: SBOM Converge Failure Semantics

This feature has no new external interface: no CLI flags, no configuration keys, no API endpoints (FR-015). Its user-facing contract is the build log and error output of existing commands (`werf build`/`converge` with SBOM enabled).

## Output contracts

### Aggregated report (extended, format preserved)

Per `wiki/pages/error-aggregation-strategy.md`, with skipped images as a new entry kind:

```
resolve external references: N of M images failed:
  - image: <name>:
      - component: <name>: resolve "purl": ...: unexpected status 404
  - image: <dependent-name>:
      - skipped: SBOM for base image "<root-name>" was not generated: <root cause>
```

- Printed on every converge exit path (happy, hard error, breaker trip).
- N counts direct failures plus skipped images.

### Resolver-unavailable terminal error

```
PURL resolver unavailable at <endpoint>: <last infrastructure error>
```

Emitted exactly once per build; accompanied by the aggregated report accumulated before the trip.

### Base-SBOM advice gating

`... rebuild it with SBOM generation enabled ...` appears only when the base image was NOT processed by the current run. For in-run bases the skip path replaces it.

### Log placement guarantees

- Deferred enrichment errors are printed inside the failing image's `image <name>: SBOM processing` block.
- External-ref resolution runs in its own named log section with a timer inside the image block.
- GOST experimental warning: at most once per process.
- `Copy SBOM artifacts into the final repo <address>` / cache messages carry the repo address.
- Multiple-artifact-entries warning names the requesting image, entry image names, and the selected entry.
