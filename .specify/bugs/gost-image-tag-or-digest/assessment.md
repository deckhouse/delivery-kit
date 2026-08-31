# Bug Assessment: E2E fixtures use unqualified external image references

- **Slug**: gost-image-tag-or-digest
- **Created**: 2026-08-31
- **Source**: https://flant.kaiten.ru/space/193531/boards/card/69452657
- **Verdict**: valid
- **Severity**: medium

## Report (verbatim or summarized)

Kaiten card reports that the `e2e_simple` GitHub Actions job fails while loading the werf configuration:

```text
Error: unable to load werf config: external image reference "registry.werf.io/werf/scratch" in `from` must include a tag (`:TAG`) or digest (`@sha256:...`)
```

The affected configuration shown in the card is:

```yaml
image: app
from: registry.werf.io/werf/scratch
```

The card links to the failing CI job: [GitHub Actions job](https://github.com/deckhouse/delivery-kit/actions/runs/33417935877/job/99574202965?pr=279). The fetched GitHub page identifies the workflow as `e2e_simple`, reports one error, and shows process exit code 201; detailed logs require GitHub authentication.

The Kaiten card was retrieved through the authenticated Kaiten/Loop MCP integration. The supplied Kaiten URL host is `flant.kaiten.ru`; URL policy branch: `confirmed-by-user` because the user explicitly requested the card data through MCP. The GitHub URL host is `github.com`; URL policy branch: `allowlisted`.

## Symptom

The E2E job fails before executing its test because werf rejects an external `from` image reference that has neither an explicit tag nor a digest. The expected behavior is for the fixture to use a qualified, resolvable image reference and for the E2E scenario to proceed without weakening werf’s validation contract.

## Reproduction

1. Run the `e2e_simple` workflow or the affected E2E scenarios from the linked CI job.
2. Initialize a test repository from an affected fixture containing `from: registry.werf.io/werf/scratch`.
3. Load the werf configuration and observe the validation error requiring `:TAG` or `@sha256:...`; the CI job exits with code 201.

The exact failing test/fixture for the linked run is not exposed by the unauthenticated GitHub page: [NEEDS CLARIFICATION: identify the first failing E2E scenario from authenticated job logs].

## Suspected Code Paths

- `pkg/config/werf.go:107-123` — `hasExplicitTagOrDigest` parses an image reference and returns true only for tagged or digested references.
- `pkg/config/werf.go:125-169` — `validateExternalImageReferences` rejects external `from` and import references without a tag or digest; this generates the reported error.
- `pkg/config/parser.go:783-787` — calls `validateExternalImageReferences` while preparing the werf configuration, before the E2E build can run.
- `pkg/config/unify_from_test.go:142-175` — unit coverage verifies that an unqualified external `from` is rejected and a tagged reference is accepted.
- `test/e2e/sbom/_fixtures/gost_toggle/state0/werf.yaml:11-13` — currently contains the unqualified `registry.werf.io/werf/scratch` reference.
- `test/e2e/sbom/_fixtures/gost_toggle/state1/werf.yaml:11-13` — currently contains the same unqualified reference.
- `test/e2e/sbom/multiplatform_test.go:42-52,108-118` — uses the `multiplatform` and `multiplatform_packages` fixtures; these current fixtures already use `:latest`.
- `test/e2e/sbom/signing_multiplatform_test.go:24-34,179-189` — uses the `signing_multiplatform` fixture; the current fixture already uses `:latest`.
- `test/e2e/vex/signing_test.go:149-159` — uses the VEX `multiplatform` fixture; the current fixture already uses `:latest`.

## Root Cause Hypothesis

**Confidence: high.** The failure is caused by a test fixture passing `registry.werf.io/werf/scratch` as an external image reference without a tag or digest. The production validator intentionally rejects this form because it would implicitly resolve to `:latest`. The current checkout already qualifies the VEX and general SBOM multi-platform fixtures with `:latest`, while the two `gost_toggle` fixtures remain unqualified and can still trigger the same failure in their scenarios. This is a test-fixture defect, not evidence that the external-reference validation should be removed or relaxed.

## Proposed Remediation

**Preferred**: Qualify every affected external scratch-image fixture with the explicitly selected tag `registry.werf.io/werf/scratch:latest`, including:

- `test/e2e/sbom/_fixtures/gost_toggle/state0/werf.yaml`
- `test/e2e/sbom/_fixtures/gost_toggle/state1/werf.yaml`
- Any additional fixture identified by the authenticated CI log for job `99574202965`.

Keep `pkg/config/werf.go` unchanged. The existing validation and unit tests encode the intended configuration contract. After updating fixtures, run the narrow GOST toggle E2E scenarios and the linked `e2e_simple` subset. Verify that `registry.werf.io/werf/scratch:latest` is available in the required test environment and that the GOST state transitions, SBOM output, and negative/positive assertions remain unchanged.

An immutable digest would improve reproducibility, but only use one after verifying that it supports the platforms required by the scenarios and matches the intended scratch image.

**Files likely to change**:

- `test/e2e/sbom/_fixtures/gost_toggle/state0/werf.yaml`
- `test/e2e/sbom/_fixtures/gost_toggle/state1/werf.yaml`
- Additional fixture paths, if confirmed by the authenticated CI log
- No production source file is expected to change

**Tests to add or update**:

- Run the GOST toggle E2E scenarios using both `state0` and `state1` fixtures.
- Re-run the affected `e2e_simple` scenario from the linked CI job.
- Verify that the tagged reference resolves and that the existing GOST/SBOM assertions still pass.
- Preserve the existing unit tests in `pkg/config/unify_from_test.go`; they already cover the relevant validation behavior.

## Risks & Considerations

- The mutable `latest` tag can change image contents and reduce test reproducibility; a verified multi-platform digest is safer if the project accepts the maintenance cost.
- The tag must resolve in the configured registry and support all platforms used by the affected E2E scenarios.
- Weakening or removing `validateExternalImageReferences` would restore implicit `:latest` behavior globally and hide malformed fixtures; that is not recommended.
- The linked GitHub page does not expose detailed logs without authentication, so the exact scenario associated with the reported run remains unverified.
- No API, user-facing behavior, migration, or security change is expected from a fixture-only remediation.

## Open Questions

- [NEEDS CLARIFICATION: Which exact fixture/scenario was the first failure in GitHub Actions job `99574202965`?]
- [NEEDS CLARIFICATION: Should the project standardize these test fixtures on `:latest`, or pin a verified immutable multi-platform digest?]
