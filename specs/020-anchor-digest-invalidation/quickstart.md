# Quickstart: Anchor Digest Invalidation

## Prerequisites

- Run from the repository root.
- Use the prepared Linux/Docker/registry test environment described by the project constitution.
- Do not run `task test:setup:environment`.
- Use existing build and signing fixtures; do not commit secrets or generated release files.

## Focused unit validation

After implementation, run the focused build tests:

```sh
task test:unit paths="./pkg/build/..." -- -focus='Anchor|Digest'
```

Expected results:

- Identical target platform, holistic inputs, build cache version, and included signing checksum inputs produce identical anchor digests.
- Changing only build cache version changes the anchor digest.
- Anchor ELF checksum inputs match the non-anchor inputs and labels; no separate enabled/disabled marker is added.
- Existing non-anchor digest sensitivity remains intact.

## Optional local-cache E2E validation

If follow-up E2E validation is desired, run the build E2E suite scoped to the feature label after adding the feature-specific label:

```sh
task test:e2e paths="./test/e2e/build/..." labelFilter="anchor-digest"
```

The optional scenario may:

1. Initialize an existing build fixture.
2. Build once with a selected cache version and signing configuration; assert the anchor is built.
3. Repeat with identical complete inputs; assert the anchor is reused and identity is unchanged.
4. Change only the build cache version; assert the prior anchor is not reused and the identity changes.
5. Repeat the warmed-cache flow with changed included signing identities; assert incompatible results are not reused. Do not require a separate digest difference solely from an enabled/disabled marker.
6. Exercise signing failure, if the existing fixture can trigger it, and assert the build fails without publishing a reusable result.

Expected cache evidence should use existing build output/report helpers and anchor identity data. Cryptographic signature verification is not required by this feature.

## Optional registry-backed validation

When the prepared registry path is available, repeat the same scenario with the existing `--repo`/registry fixture options and insecure local-registry flags. This remains optional follow-up validation.

## Required repository gates

For this plan, the mandatory validation sequence is:

```sh
task format
task build
task deps:install:golangci-lint
task lint
task test:unit
```

The build E2E and integration commands remain available as optional follow-up validation for the complete cache flow.
