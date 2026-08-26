# Quickstart: SBOM Checksum Completeness Validation

**Feature**: specs/019-sbom-checksum-completeness

## Prerequisites

- Linux with Docker and the pre-configured e2e environment (kind, registry) — already set up per constitution.
- `task deps:install:golangci-lint` once per session.

## Unit-level validation (SC-003)

```bash
task test:unit paths="./pkg/build/..."
```

Expected: checksum table tests pass — flipping any single input (scan opts, merge opts, gost attack surface, gost security function, signer identity, target platform) changes the checksum; identical inputs give identical checksums.

## E2E validation (SC-001, SC-002)

```bash
task test:e2e paths="./test/e2e/sbom/..." labelFilter="sbom"
```

Expected scenario (GOST toggle, `gost_cache_invalidation_test.go`):

1. Build a scratch image with GOST yes/yes → SBOM attached with GOST properties.
2. Rebuild with no changes → log shows "Use previously generated SBOM from registry" (cache reuse).
3. Change only the GOST config (fixture state change), rebuild → no stage is rebuilt, build log shows SBOM regeneration, new SBOM carries the updated GOST properties.

## Full gate sequence (before handover)

```bash
task format
task build
task lint
task test:unit
task test:e2e paths="./test/e2e/sbom/..." labelFilter="sbom"
task test:integration
```

## References

- Contract: [contracts/checksum.md](./contracts/checksum.md)
- Input inventory: [data-model.md](./data-model.md)
- Decisions: [research.md](./research.md)
