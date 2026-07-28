# Quickstart: Batch Purl-Resolver Errors

## Prerequisites

- Go 1.24.10+
- `task` installed (Task runner)
- `WERF_EXTERNAL_REFS_SERVER_URL` environment variable configured (or mock server for testing)

## Unit Tests

### Run the specific unit tests

```bash
task test:unit -- -run "TestBatchPurl" ./pkg/build/
task test:unit -- ./pkg/sbom/externalref/
```

### Expected outcomes

1. **Happy path**: All images with valid PURLs → build succeeds, no error
2. **Mixed failures across sets**: PURL failures → single aggregated error with hierarchical format:
   ```
   resolve external references: N of M images failed:
     - image: <name>:
         - component: <component>: <err>
   ```
3. **All fail**: All images across all sets fail → aggregated error with all per-image component details
4. **Non-PURL error**: Env var missing → immediate error (not aggregated)
5. **Empty set**: No images → no error
6. **Successful images preserved**: Succeeding images have valid SBOMs even when others fail
7. **ComponentError**: `Error()` returns component details inline, `ComponentDetails()` returns just the details lines
8. **No logboek**: `Enricher.Enrich` does not log individual component failures

## E2E Tests

### Run the e2e test for batch PURL errors

```bash
task test:e2e -- labelFilter="purl-resolver-errors"
```

### E2E test scenario

Location: `test/e2e/sbom/purl_resolver_errors_test.go`  
Fixture: `test/e2e/sbom/_fixtures/purl_resolver_errors/`

Uses `httptest` HTTP mock server with 3 images:

- **image-fail-all**: 2 PM components (curl, openssl), both return 404
- **image-fail-partial**: 2 PM components (curl, jq), curl returns 404, jq returns 200
- **image-ok**: 1 PM component (jq), returns 200

Expected outcomes:
- Build fails with a single aggregated error
- Error mentions `image-fail-all` and `image-fail-partial` with component details
- Error does NOT mention `image-ok`
- `image-ok` SBOM is produced with valid external references
- Error format: `"resolve external references: %d of %d images failed:\n  - image: ... :\n      - component: ..."`

## Manual Verification

### Scenario: Build with mixed PURL resolution outcomes

1. Create a project with images in different dependency levels
2. Set `WERF_EXTERNAL_REFS_SERVER_URL` to a service that resolves only some PURLs
3. Run:

```bash
task build
./bin/werf build --repo <registry>
```

4. Verify:
   - All images processed for SBOM generation
   - Images with resolvable PURLs produce valid SBOM artifacts
   - Build fails with a SINGLE aggregated error containing hierarchical image→component details

### Scenario: Pre-condition failure

1. Unset `WERF_EXTERNAL_REFS_SERVER_URL`
2. Run build → verify immediate failure (not aggregated)

## Test Structure

Key test files:

| File | Type | What it tests |
|------|------|---------------|
| `pkg/build/build_phase_purl_test.go` | Unit | PURL error aggregation in `convergeSbomByImagesSets` |
| `pkg/sbom/externalref/enricher_test.go` | Unit | `ComponentError` format, `ComponentDetails()`, no logboek |
| `test/e2e/sbom/purl_resolver_errors_test.go` | E2E | 3-image build with httptest mock, hierarchical error format |