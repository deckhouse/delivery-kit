## 1. SBOM Enable State in Stage Digest

- [x] 1.1 Modify `calculateDigest` in `pkg/build/build_phase.go` to conditionally append `"sbom_enabled"` as an extra checksum argument only when `conveyor.EnableSbom()` returns `true`. When `EnableSbom()` is `false`, no extra argument is added — digest behavior is unchanged.
- [x] 1.2 Verify that the `calculateDigest` function receives the `conveyor` parameter with the SBOM enable state accessible at the call site

## 2. Testing

- [x] 2.1 Add unit test for `calculateDigest` verifying that:
  - Digest is unchanged when `EnableSbom()` returns `false` (backward compatibility)
  - Digest changes when `EnableSbom()` returns `true`
  - Digest returns to its original value when `EnableSbom()` goes back to `false`
- [x] 2.2 Run existing unit tests to confirm no regressions (`task test:unit`)
- [x] 2.3 Add E2E tests covering SBOM caching scenarios:
  - Without `build.sbom.enable` (default): stages are cached without SBOM
  - With `build.sbom.enable=false`: stages are cached, existing cache is reused
  - With `build.sbom.enable=true`: stage cache is invalidated, stages are rebuilt with SBOM
- [x] 2.4 Run E2E tests to confirm SBOM caching works (`task test:e2e labelFilter="sbom && caching" paths="./test/e2e/sbom`)

## 3. Validation

- [x] 3.1 Run `task format` to verify code formatting
- [x] 3.2 Run `task test:unit` to confirm all unit tests pass
- [x] 3.3 Run `task test:e2e` to confirm SBOM caching E2E tests pass