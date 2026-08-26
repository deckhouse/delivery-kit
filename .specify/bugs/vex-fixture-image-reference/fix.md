# Bug Fix: Qualify multi-platform VEX and SBOM fixture image references

- **Slug**: vex-fixture-image-reference
- **Fixed**: 2026-08-27
- **Assessment**: ./assessment.md
- **Status**: applied

## Summary

Updated all affected multi-platform VEX and SBOM fixtures to use the explicit `latest` tag required by external image reference validation. The tag resolves to a multi-platform manifest supporting both required Linux platforms, and the scoped VEX and SBOM E2E scenarios reach their build paths successfully.

## Changes

| File | Change | Notes |
|------|--------|-------|
| `test/e2e/vex/_fixtures/multiplatform/werf.yaml` | modified | Qualified the external scratch image with `:latest`; VEX configuration remained unchanged. |
| `test/e2e/sbom/_fixtures/multiplatform/werf.yaml` | modified | Qualified the external scratch image with `:latest`; SBOM configuration remained unchanged. |
| `test/e2e/sbom/_fixtures/multiplatform_packages/werf.yaml` | modified | Qualified the external scratch image with `:latest`; package configuration remained unchanged. |
| `test/e2e/sbom/_fixtures/signing_multiplatform/werf.yaml` | modified | Qualified the external scratch image with `:latest`; signing configuration remained unchanged. |

## Diff Highlights

```yaml
-from: registry.werf.io/werf/scratch
+from: registry.werf.io/werf/scratch:latest
```

The same one-line fixture change was applied to all four assessed multi-platform fixtures.

## Tests Added or Updated

- No tests were added or updated. Existing E2E coverage was used as requested.
- VEX `US1: multi-platform build publishes one signed VEX bundle at the index digest` — previously verified as passed, including index-level VEX bundle and platform-level artifact assertions.
- SBOM multi-platform scenarios using `multiplatform`, `multiplatform_packages`, and `signing_multiplatform` fixtures — scoped verification completed without failures.

## Local Verification

- Commands run: `docker manifest inspect registry.werf.io/werf/scratch:latest` → passed; returned a manifest list with `linux/amd64` and `linux/arm64` entries.
- Commands run: `task test:e2e paths="./test/e2e/vex/..." labelFilter="VEX && signing && simple" parallel=1` → passed on retry: 1 selected spec passed, 0 failed, 8 skipped. The initial bounded 120-second attempt timed out during setup.
- Commands run: `task test:e2e paths="./test/e2e/sbom/..." labelFilter="sbom && multiplatform" parallel=1` → passed: 1 selected spec passed, 0 failed, 63 pending, 108 skipped. Pending cases are unsupported Buildah variants in the local environment.
- Manual checks: Confirmed the fixture references are qualified and that no production source, VEX assertion, SBOM assertion, or test code was changed.

## Deviations from Assessment

None. The report was expanded to cover the additional SBOM fixtures identified by the updated assessment and CI evidence.

## Follow-ups

- Consider replacing the mutable `latest` tag with a verified immutable multi-platform digest when the fixture reproducibility requirement permits it.
- Run the full CI matrix if validation of the pending Buildah variants is required.
