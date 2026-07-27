# Quickstart: Batch Purl-Resolver Errors

## Prerequisites

- Go 1.24.10+
- `task` installed (Task runner)
- `WERF_EXTERNAL_REFS_SERVER_URL` environment variable configured (or mock server for testing)

## Unit Tests

### Run the specific unit tests

```bash
task test:unit -- -run "TestBatchPurl" ./pkg/build/
```

Or run all build unit tests:

```bash
task test:unit -- ./pkg/build/
```

### Expected outcomes

1. **Happy path**: All images with valid PURLs → build succeeds, no error
2. **Mixed failures across sets**: 2 images in set A and 1 image in set B fail PURL resolution → single aggregated error `"resolve external references: 3 of N images failed"`
3. **All fail**: All images across all sets fail → `"resolve external references: N of N images failed"`
4. **Single image fail**: 1 image in a single set fails → `"resolve external references: 1 of 1 images failed"`
5. **Non-PURL error**: Env var missing → immediate error (not aggregated)
6. **Empty set**: No images → no error
7. **Successful images preserved**: Succeeding images have valid SBOMs even when others fail

## Manual Verification

### Scenario: Build with mixed PURL resolution outcomes across multiple image sets

1. Create a project with images in different dependency levels (multiple image sets)
2. Ensure `WERF_EXTERNAL_REFS_SERVER_URL` points to a service that resolves only some PURLs
3. Run the build:

```bash
task build
./bin/werf build --repo <registry>
```

4. Verify:
   - All images across all sets are processed for SBOM generation
   - Images with resolvable PURLs produce valid SBOM artifacts
   - Build fails with a SINGLE aggregated error: `"resolve external references: N of M images failed"` covering ALL image sets

### Scenario: Pre-condition failure

1. Unset `WERF_EXTERNAL_REFS_SERVER_URL`
2. Run build → verify immediate failure with `"WERF_EXTERNAL_REFS_SERVER_URL env var is required"` (not aggregated)

## Test Structure

Tests should be co-located in `pkg/build/build_phase_test.go` using Ginkgo + Gomega.

Key test scenarios (see [data-model.md](data-model.md) for entity definitions and [contracts/README.md](contracts/README.md) for error contract):

- `convergeSbomByImagesSets` with mock `ExternalRefPatcher` returning errors across multiple image sets
- `convergeSbomByImagesSets` with mixed success/failure outcomes across sets
- `convergeSbomByImagesSets` with pre-condition error (non-PURL)
- `convergeSbomByImagesSets` with empty image set
- Verify error format: `"resolve external references: N of M images failed"` covering all sets
- Verify successful images still produce SBOMs