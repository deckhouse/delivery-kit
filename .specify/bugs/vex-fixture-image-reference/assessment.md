# Bug Assessment: VEX fixture uses an unqualified external image reference

- **Slug**: vex-fixture-image-reference
- **Created**: 2026-08-26
- **Source**: https://flant.kaiten.ru/space/193531/boards/card/69265905
- **Verdict**: valid
- **Severity**: medium

## Report (verbatim or summarized)

Kaiten card [69265905](https://flant.kaiten.ru/space/193531/boards/card/69265905), “Исправить VEX fixture: добавить tag или digest для внешнего образа”.

The VEX E2E tests fail during werf configuration loading with:

```text
Error: unable to load werf config: external image reference "registry.werf.io/werf/scratch" in `from` must include a tag (`:TAG`) or digest (`@sha256:...`)
```

The reported CI job is `32871264280-3`, started through `task test:e2e:simple`. The affected fixture is `test/e2e/vex/_fixtures/multiplatform/werf.yaml:9`, which currently contains:

```yaml
from: registry.werf.io/werf/scratch
```

The requested change is to add the agreed `latest` tag and verify the VEX multi-platform test. The selected `latest` reference must resolve to a multi-platform manifest supporting both `linux/amd64` and `linux/arm64`. The fix must not change the VEX semantics being tested.

The supplied URL host is `flant.kaiten.ru`. The ordinary page fetch returned the Kaiten login page; the card content was retrieved through the authenticated Kaiten integration after the user explicitly requested reading the card context.

- URL policy branch: `confirmed-by-user`

## Symptom

The VEX multi-platform E2E fixture cannot be loaded because its external base image reference has neither an explicit tag nor a digest. The expected behavior is that the fixture loads and the VEX multi-platform test proceeds while preserving the same base image identity and VEX assertions.

## Reproduction

1. Run the VEX multi-platform test, which initializes a repository from the `multiplatform` fixture and builds the `app` image.
2. During werf configuration loading, process `test/e2e/vex/_fixtures/multiplatform/werf.yaml`.
3. Observe configuration validation fail for `from: registry.werf.io/werf/scratch` because the external reference is unqualified.

The failure occurred in job `32871264280-3` during `task test:e2e:simple`. The required verification is the point-specific VEX multi-platform scenario, not the full E2E suite. The test environment is already configured. Subsequent CI evidence shows that the same validation failure also affects SBOM multi-platform scenarios using separate fixtures.

## Suspected Code Paths

- `test/e2e/vex/_fixtures/multiplatform/werf.yaml:8-14` — defines the `app` image used by the multi-platform VEX fixture; line 9 contains the external image reference. This fixture now contains the agreed `:latest` tag in the current checkout.
- `test/e2e/sbom/_fixtures/signing_multiplatform/werf.yaml:11-16` — defines the fixture used by the failing SBOM multi-platform signing tests; line 12 still contains the unqualified external image reference.
- `test/e2e/sbom/_fixtures/multiplatform/werf.yaml:11-16` — defines the fixture used by the general SBOM multi-platform test and still contains the same unqualified reference.
- `test/e2e/sbom/_fixtures/multiplatform_packages/werf.yaml:11-21` — defines the fixture used by the SBOM multi-platform packages test and still contains the same unqualified reference.
- `test/e2e/vex/signing_test.go:148-171` — the VEX multi-platform scenario initializes the `multiplatform` fixture and invokes the build that reaches configuration loading.
- `test/pkg/suite_init/suite_data.go:82-88` — `InitTestRepo` copies the fixture into a temporary test repository and commits it before the E2E build.
- `pkg/config/werf.go:110-123` — `hasExplicitTagOrDigest` recognizes only tagged or digested image references.
- `pkg/config/werf.go:125-169` — `validateExternalImageReferences` rejects external `from` and import references without a tag or digest.
- `pkg/config/unify_from_test.go:142-175` — unit coverage establishes that an unqualified external `from` is rejected and a tagged reference is accepted.

## Root Cause Hypothesis

**Confidence: high.** The affected fixtures were authored with `registry.werf.io/werf/scratch` as an external image reference without `:TAG` or `@sha256:...`. Since it is not an image defined inside the werf configuration, `validateExternalImageReferences` applies the explicit tag/digest requirement and returns the reported error before the E2E build can run. The VEX fixture was updated, but the separate SBOM multi-platform fixtures remained unchanged, so `task test:e2e:simple` still fails. This is a fixture coverage issue, not an indication that the VEX or SBOM implementation is incorrect.

## Proposed Remediation

**Preferred**: Update every affected multi-platform fixture so the external image uses the agreed explicit tag `registry.werf.io/werf/scratch:latest`:

- `test/e2e/vex/_fixtures/multiplatform/werf.yaml`
- `test/e2e/sbom/_fixtures/multiplatform/werf.yaml`
- `test/e2e/sbom/_fixtures/multiplatform_packages/werf.yaml`
- `test/e2e/sbom/_fixtures/signing_multiplatform/werf.yaml`

Verify that this tag resolves to a multi-platform manifest supporting both `linux/amd64` and `linux/arm64`. This is a fixture-only change that satisfies the existing configuration contract without changing the VEX or SBOM implementations and assertions.

Using `latest` is less reproducible than an immutable digest, but it is the explicitly selected reference for this task.

**Files likely to change**:

- `test/e2e/vex/_fixtures/multiplatform/werf.yaml`
- `test/e2e/sbom/_fixtures/multiplatform/werf.yaml`
- `test/e2e/sbom/_fixtures/multiplatform_packages/werf.yaml`
- `test/e2e/sbom/_fixtures/signing_multiplatform/werf.yaml`
- No production source change is expected.

**Tests to add or update**:

- Run the point-specific VEX multi-platform scenario in `test/e2e/vex/signing_test.go` and verify it reaches the build and retains its existing index-level VEX bundle and platform-level artifact assertions.
- Run the SBOM multi-platform scenarios that use `multiplatform`, `multiplatform_packages`, and `signing_multiplatform` fixtures; the CI log specifically identifies the signing scenarios as currently failing.
- Confirm that `registry.werf.io/werf/scratch:latest` resolves for both required platforms in the configured test environment.
- The existing unit tests in `pkg/config/unify_from_test.go` already cover the relevant tag/digest validation and do not need modification because the selected `latest` reference is a standard tagged reference.

## Risks & Considerations

- The `latest` tag must resolve in `registry.werf.io` to a multi-platform manifest usable for both `linux/amd64` and `linux/arm64`; an incorrect or single-platform image could cause a build failure after configuration loading succeeds.
- Changing from an unqualified reference to `:latest` changes only the fixture's image reference resolution, not the VEX document or assertions, but the referenced image contents may affect build behavior.
- A mutable `latest` tag can change over time and reduce test reproducibility; this is accepted for the current task and could be replaced by a verified digest later.
- Only the fixture is in scope; production config, build, SBOM, and VEX sources must remain unchanged.
- The configured CI environment is available for the point-specific test.

## CI Follow-up

The attached CI log `5_e2e_simple.txt` confirms that the remaining failure is caused by an unmodified SBOM fixture, not by a new production-code error. The runner reports the exact unqualified reference:

```text
from: registry.werf.io/werf/scratch
```

The failures are in `test/e2e/sbom/signing_multiplatform_test.go` for both signed and unsigned scenarios. Those scenarios call `InitTestRepo(..., "signing_multiplatform")`, which uses `test/e2e/sbom/_fixtures/signing_multiplatform/werf.yaml`; that file still has the unqualified reference. The VEX fixture in the current checkout already has `:latest`, but the separate SBOM fixtures do not. The log therefore does not show `:latest` being tried and rejected.

## Open Questions

- None. The selected reference is `registry.werf.io/werf/scratch:latest`, it must support `linux/amd64` and `linux/arm64`, the change is limited to the fixture, and the configured environment is available for the point-specific VEX multi-platform test.
