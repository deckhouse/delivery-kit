# Implementation Plan: ELF Signing Anchor Digest

**Branch**: `020-elf-signing-anchor-digest` | **Date**: 2026-08-31 | **Spec**: [spec.md](spec.md)

**Input**: Feature specification from `/specs/020-elf-signing-anchor-digest/spec.md`

## Summary

Extend the private anchor branch of `calculateDigest` in `pkg/build/build_phase.go` so it includes the same conditional, stable ELF signing identities already present in the non-anchor checksum contract: the BSign key fingerprint, and the in-house signing certificate and certificate chain. Keep secrets and standalone signing-state markers out of the digest, preserve the existing hash ordering and cache lookup behavior, document the `sign` stage's existing certificate coverage, and add focused Ginkgo/Gomega tests for determinism, sensitivity, secret exclusion, and contract alignment.

## Technical Context

**Language/Version**: Go 1.24.10

**Primary Dependencies**:
- Existing werf build/signing packages and `github.com/werf/common-go/pkg/util` hashing helpers.
- Ginkgo v2 and Gomega for co-located unit tests.
- No new dependencies.

**Storage**: Existing local and secondary OCI stage storage; no storage schema changes.

**Testing**: Focused and package unit tests using Ginkgo + Gomega. E2E cache validation is optional follow-up coverage, not the acceptance gate for this feature.

**Target Platform**: Existing werf build targets; digest logic is platform-aware through `TargetPlatform`.

**Project Type**: Go CLI tool; this feature changes private build cache identity calculation only.

**Performance Goals**: Preserve current digest calculation complexity and cache lookup behavior; append at most three existing string inputs.

**Constraints**: Do not include private key bytes or passphrases. Do not add a signing enabled/disabled marker. Keep labels, values, and conditions aligned with the existing non-anchor checksum contract. Do not change public APIs, CLI syntax, dependencies, cryptographic implementation, or registry protocols.

**Scale/Scope**: One private digest function, its focused tests, and feature design artifacts.

## Constitution Check

*GATE: Must pass before Phase 0 research. Re-check after Phase 1 design.*

- **Simplicity over abstraction**: PASS. Reuse the existing digest function and signing option fields; no new interface or helper is required.
- **Go idioms and minimal public surface**: PASS. The change remains private to `pkg/build`; no public API is added.
- **Dependency rules**: PASS. No dependency changes.
- **Test-before-merge**: PASS by plan. Tests will be co-located and use Ginkgo/Gomega.
- **Build and quality gates**: PASS by plan. Implementation validation will use `task format`, `task build`, `task deps:install:golangci-lint`, `task lint`, `task test:unit`, scoped e2e, and integration commands as required by the repository.
- **Scope and generated files**: PASS. No CHANGELOG, release notes, CLI reference, or generated workflow files are changed.

No violations require complexity tracking.

## Project Structure

### Documentation (this feature)

```text
specs/020-elf-signing-anchor-digest/
├── plan.md
├── research.md
├── data-model.md
├── quickstart.md
├── contracts/
│   └── anchor-digest.md
└── spec.md
```

### Source Code (planned changes)

```text
pkg/build/
├── build_phase.go             # Add signing identities to anchor digest inputs
└── content_digest_test.go     # Focused anchor/non-anchor contract tests
```

**Structure Decision**: Keep the implementation in the existing `pkg/build` digest path and extend the existing anchor test suite. No new package, public type, CLI command, storage abstraction, or dependency is warranted.

## Phase 0: Research

Completed in [`research.md`](research.md).

- Located the anchor and non-anchor branches in `calculateDigest`.
- Confirmed the non-anchor branch's authoritative signing conditions, values, and labels.
- Confirmed `ELFSigningOptions` exposes stable fingerprint data separately from the passphrase.
- Confirmed `SignStage.GetDependencies` already covers manifest signing certificate and chain.
- Selected focused unit tests as the required acceptance gate.

## Phase 1: Design

Completed in [`data-model.md`](data-model.md), [`contracts/anchor-digest.md`](contracts/anchor-digest.md), and [`quickstart.md`](quickstart.md).

Implementation steps:

1. Update the anchor input assembly in `calculateDigest` to conditionally append the three stable signing values under the same conditions and labels used by the non-anchor branch.
2. Add the required non-obvious implementation documentation near the anchor digest calculation, explicitly noting that the `sign` stage already accounts for manifest signing certificate and chain inputs and that the anchor must not duplicate them inconsistently.
3. Extend `pkg/build/content_digest_test.go` with Ginkgo/Gomega cases covering:
   - deterministic anchor digests for identical signing inputs;
   - changed BSign fingerprint changes the anchor digest;
   - changed in-house certificate changes the anchor digest;
   - changed in-house certificate chain changes the anchor digest;
   - private key/passphrase values do not affect the digest when not applicable;
   - disabled/absent signing does not add a standalone marker;
   - anchor and non-anchor paths respond to the same applicable identity values and preserve labels/conditions.
4. Keep existing holistic-input filtering, SBOM behavior, and cache lookup/storage code unchanged.

### Post-design Constitution Check

- **Simplicity**: PASS; one existing function and one existing test file are extended.
- **Correctness and alignment**: PASS; tests assert the existing non-anchor contract rather than introducing a second contract.
- **Security**: PASS; secret fields are explicitly excluded from digest inputs.
- **Public surface/dependencies**: PASS; unchanged.
- **Required verification**: PASS by plan; validation commands are recorded in [`quickstart.md`](quickstart.md).

## Complexity Tracking

No constitution violations or complexity exceptions.
