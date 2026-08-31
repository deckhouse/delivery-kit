# Implementation Plan: Systemic Anchor Digest Invalidation

**Branch**: `020-anchor-digest-invalidation` | **Date**: 2026-08-31 | **Spec**: [spec.md](spec.md)

**Input**: Feature specification from `/specs/020-anchor-digest-invalidation/spec.md`

## Summary

Fix the anchor branch of `pkg/build/build_phase.go` so its digest includes the explicit build cache version and the same ELF signing checksum components as the non-anchor path. Do not add a separate enabled/disabled signing marker or mode tag. Preserve the existing non-anchor digest contract and public CLI/API surface. Prove the behavior with focused Ginkgo/Gomega unit tests; warmed-cache E2E validation is optional follow-up coverage and is not required for these changes.

## Technical Context

**Language/Version**: Go 1.24.10

**Primary Dependencies**: Existing `pkg/build`, `pkg/build/signing`, `pkg/image`, test helpers, Ginkgo/Gomega, and current container/cache backends. No new dependency.

**Storage**: Existing local stage cache and optional OCI registry-backed stage cache.

**Testing**: Ginkgo + Gomega unit tests are required. E2E coverage is optional follow-up validation and is not part of the mandatory implementation scope.

**Target Platform**: Linux amd64/arm64 build paths; prepared Docker/Buildah and registry test environment.

**Project Type**: Go CLI with internal build/cache logic.

**Performance Goals**: Preserve current digest computation cost and cache reuse for identical complete inputs; add only a small bounded number of scalar identity inputs.

**Constraints**: No secret signing material in the digest; no new external dependency; no public API or command syntax change; preserve non-anchor behavior. E2E coverage is not mandatory for these changes. `BuildCacheVersion` must be an explicit internal input to `calculateDigest`, not read there indirectly from package-global state.

**Unknowns resolved by research**: The current anchor early return omits `BuildCacheVersion` and ELF-signing checksum components; the anchor path must reuse the non-anchor component names and conditional values without encoding the signing enabled/disabled fact separately.

## Constitution Check

*GATE: Must pass before Phase 0 research. Re-check after Phase 1 design.*

- **Simplicity:** PASS. Modify the existing internal digest path; no new abstraction or persistence layer.
- **Idiomatic Go/minimal public surface:** PASS. Keep changes private to build digest construction and co-located tests; wrap new errors only if introduced.
- **Dependency boundaries:** PASS. `pkg/build` consumes existing `pkg/image` and signing types; no `cmd` dependency and no dependency additions.
- **Testing:** PASS. Required new tests use Ginkgo/Gomega and live alongside the source; E2E tests are optional and are not a gate for this scope.
- **Security:** PASS. Only stable non-secret fingerprint/certificate identity is included; private keys and passphrases are excluded.
- **Quality gates:** PASS. Use `task format`, `task build`, lint prerequisite/lint, and unit commands for this scope; E2E and integration are optional follow-up validation.

No constitution violations require a complexity exception.

## Project Structure

```text
specs/020-anchor-digest-invalidation/
├── plan.md
├── research.md
├── data-model.md
├── quickstart.md
└── contracts/
    └── cache-key-contract.md

pkg/build/build_phase.go                 # anchor cache-key implementation
pkg/build/*_test.go                      # focused digest tests, co-located
test/e2e/build/*_test.go                 # optional follow-up E2E coverage
```

**Structure Decision**: Keep implementation in the existing `pkg/build` digest path and extend the existing co-located unit coverage. E2E coverage may be added later, but is not required. No new package, public type, migration, or external contract is needed.

## Phase 0: Research

Completed in [research.md](research.md):

1. Trace `calculateStage` and `calculateDigest` to confirm the anchor early return.
2. Compare anchor and non-anchor cache-key inputs.
3. Trace `ELFSigningOptions` construction and existing stable fingerprint/certificate signals.
4. Inspect existing signing and digest tests; treat E2E fixtures as optional follow-up context rather than a mandatory implementation dependency.
5. Select a minimal internal fix and explicitly exclude secret material.
6. Establish the required data flow: `imagePkg.BuildCacheVersion` → `calculateStage` → `calculateDigestOptions.BuildCacheVersion` → `calculateDigest`.

## Phase 1: Design & Contracts

Completed in [data-model.md](data-model.md), [contracts/cache-key-contract.md](contracts/cache-key-contract.md), and [quickstart.md](quickstart.md):

1. Define the anchor result and digest identity invariants.
2. Define explicit ordered cache-key inputs and state distinctions.
3. Define required unit validation and optional E2E follow-up scenarios, plus repository gates.

## Implementation Approach

1. Add `BuildCacheVersion string` to the internal `calculateDigestOptions` contract. In `calculateStage`, populate it explicitly from the existing `imagePkg.BuildCacheVersion` value before calling `calculateDigest`; `calculateDigest` must not obtain the version indirectly from package-global state.
2. Refactor the anchor portion of `calculateDigest` in `pkg/build/build_phase.go` so it consumes `opts.BuildCacheVersion` and appends it as a stable cache-key input before hashing.
3. Align anchor ELF-signing inputs with the existing non-anchor logic: use the same `ELFSigningOptions.Enabled()` guard and the same input values and labels — `ELF_SIGNING_PGP_KEY_FINGERPRINT`, `MANIFEST_SIGNING_CERTIFICATE`, and `SIGNING_CERTIFICATE_CHAIN`. Do not add a separate enabled/disabled marker, mode tag, or divergent fallback; do not include passphrases or private key bytes.
4. Add a concise, non-obvious comment to `calculateDigest` explaining that the `sign` stage already accounts for the relevant checksum components, so the digest inputs must not duplicate or diverge from that stage’s checksum contract.
5. Pass the same explicit `opts.BuildCacheVersion` through the non-anchor path, preserving its current effective `BuildCacheVersion`, stage, dependency, previous-stage, base-image, SBOM, and signing contributions and ordering unless focused tests expose a concrete regression.
6. Add Ginkgo/Gomega unit coverage proving that `calculateDigest` changes when the explicitly supplied `BuildCacheVersion` changes, without mutating or relying on global state. Cover anchor determinism, matching ELF checksum inputs, signing identity changes, secret exclusion by construction, and unchanged non-anchor behavior. Avoid hand-written mocks and avoid changing unrelated existing tests.
7. Treat warmed-cache E2E validation as optional follow-up coverage, not as a mandatory deliverable or gate for these changes.

## Complexity Tracking

None. The design deliberately avoids a new cache-key type, public API, dependency, or storage schema.

## Post-design Constitution Check

- **Simplicity/minimal surface:** PASS — one existing internal digest path and existing test suites.
- **Security:** PASS — identity-only signing inputs, no secret material.
- **Test-before-merge:** PASS — deterministic unit tests are required; warmed-cache E2E coverage is optional for this scope.
- **Compatibility:** PASS — non-anchor behavior and CLI/API remain unchanged; `BuildCacheVersion` becomes an explicit internal input only.
- **Gates:** PASS — required unit/build/lint validation is recorded in [quickstart.md](quickstart.md); E2E is explicitly optional.
