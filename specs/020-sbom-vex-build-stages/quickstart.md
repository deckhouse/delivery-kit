# Quickstart Validation: SBOM and VEX Build Stages

## Prerequisites

- Linux test environment with Docker, kind, and a writable OCI registry already configured.
- A fixture containing at least one final image and a VEX document.
- `--repo` configured for every build that enables SBOM or VEX.

## Unit validation

Run the focused build/stage and artifact tests first:

```text
task test:unit paths="./pkg/build/..."
task test:unit paths="./pkg/oci/artifact/..."
task test:unit paths="./pkg/vex/..."
```

Expected results:

- Artifact stages calculate stable dependencies and remain non-buildable/mutable.
- Single-platform SBOM/VEX subjects resolve to the manifest digest.
- Multi-platform SBOM subjects resolve per platform and VEX resolves to the index digest.
- Propagation skips identical repositories, deduplicates existing identities, and distinguishes final errors from cache warnings.
- Local-only artifact-enabled builds fail before any image stage is executed.

## End-to-end validation

Run the SBOM suite with the feature label/path:

```text
task test:e2e paths="./test/e2e/sbom/..." labelFilter="sbom"
```

Cover these repository combinations:

1. Primary only with SBOM and VEX.
2. Primary plus final repository.
3. Primary plus one or more cache repositories.
4. Primary plus final and cache repositories.
5. Secondary repository restore into primary storage.
6. Identical primary/final/cache addresses.
7. Two-platform image.
8. Unavailable final repository, unavailable cache repository, and local-only artifact-enabled build.

For each successful case, retrieve artifact descriptors by the actual image digest from every repository containing the image. Verify that repeated builds do not add duplicate fallback-index entries.

Then run the repository integration suite:

```text
task test:integration
```

Expected outcome: existing builds without SBOM/VEX retain their behavior, and existing cleanup removes orphan fallback artifact indexes in all propagated repositories.
