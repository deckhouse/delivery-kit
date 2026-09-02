# Implementation Plan: SBOM and VEX Build Stages

**Branch**: `020-sbom-vex-build-stages` | **Date**: 2026-09-01 | **Spec**: [spec.md](./spec.md)

**Input**: Feature specification from `/specs/020-sbom-vex-build-stages/spec.md`

## Summary

Move SBOM and VEX generation out of the `BuildPhase.AfterImages` post-build pass and replace the `sbomStep` and `vexStep` implementations with registry-backed, non-buildable mutable stages modeled after `pkg/build/stage/sign.go`. The new `SbomStage` and `VexStage` become the sole owners of SBOM/VEX cache identity, generation, signing, attestation publication, and fallback-index interaction. Unlike ordinary image stages, they are associated with the final image digest, operate on the associated OCI artifact rather than on the image filesystem or image layers, and perform all registry operations through `StorageManager`, which routes them to the appropriate primary, secondary, cache, or final `StagesStorage`.

Artifact publication will use explicit source and destination image descriptors. SBOM remains platform-specific; VEX is attached once at the top-level image index for multi-platform images and to the image manifest for single-platform images. A shared idempotent propagation operation will cover primary-to-final, primary-to-cache, and secondary-to-primary copies, resolving the destination digest and preserving fatal final-repository versus best-effort cache error policies.

## Technical Context

**Language/Version**: Go 1.24.10

**Primary Dependencies**:
- Existing build stage interfaces and lifecycle in `pkg/build/stage`, `pkg/build`, and `pkg/build/conveyor.go`.
- Existing SBOM domain primitives in `pkg/sbom/...`, to be moved into `SbomStage`.
- Existing VEX domain primitives in `pkg/vex/...`, to be moved into `VexStage`.
- Existing `pkg/build/sbom_step.go` and `pkg/build/vex_step.go` are transitional sources only and must be removed after their logic is migrated.
- Existing OCI artifact and fallback-index operations in `pkg/oci/artifact` and `pkg/attestation`.
- Existing registry/storage copy operations in `pkg/storage`, `pkg/storage/manager`, and `pkg/docker_registry`.
- `StorageManager` is the required registry boundary for `SbomStage`, `VexStage`, and propagation. It owns the primary, secondary, cache, and final `StagesStorage` instances and must route each operation to the correct repository abstraction. `StagesStorage` may be extended with minimal OCI-artifact primitives, but stages must not select repositories or call concrete registry clients directly.
- Existing signing options in `pkg/build/signing`.
- Ginkgo + Gomega test framework and existing e2e fixtures.

**Storage**: OCI registry for image manifests/indexes and fallback-tag artifact indexes, accessed through `StorageManager`, which routes operations to primary, secondary, cache, and final `storage.StagesStorage` instances; local Buildah/container storage remains supported when artifacts are disabled.

**Testing**: Co-located Ginkgo/Gomega unit tests, existing `test/e2e/sbom` and `test/e2e/vex` suites, and legacy integration tests.

**Target Platform**: Linux amd64/arm64; single- and multi-platform image builds.

**Project Type**: Go CLI with a staged image build conveyor.

**Performance Goals**: Remove duplicate post-build SBOM/VEX passes, preserve stage cache hits, avoid duplicate artifact copies, and retain existing parallel image processing.

**Constraints**:
- Preserve fallback-tag artifact storage and existing artifact readers.
- Do not represent artifacts as image layers or migrate to OCI Referrers.
- Do not add dependencies or change repository flag semantics.
- Registry destination validation must happen before image building when SBOM/VEX is enabled.
- Final-repository artifact failures are fatal; cache-repository failures remain best effort.

## Constitution Check

*GATE: Must pass before Phase 0 research. Re-checked after Phase 1 design.*

- **Simplicity over abstraction**: PASS. Use two explicit stages, `SbomStage` and `VexStage`, instead of retaining parallel step and stage abstractions. Add one focused shared propagation path rather than duplicating repository-copy logic.
- **Stage distinction**: PASS. The plan explicitly requires that SBOM/VEX stages are final-image-digest-associated OCI-artifact stages, not ordinary image-mutating stages, and that registry access goes through `StorageManager` and its repository-specific `storage.StagesStorage` abstractions.
- **Go idioms and errors**: PASS. New public methods, if required, take `context.Context` first; errors wrap operation context; stage-specific helpers remain private where possible.
- **Minimal public surface**: PASS. Artifact stages and propagation contracts are internal to `pkg/build`; no new CLI flags or external API are planned.
- **Testing**: PASS. Tests remain alongside source and use Ginkgo/Gomega. E2E coverage extends existing SBOM/VEX suites rather than introducing a parallel harness.
- **Dependencies**: PASS. No external dependency changes.
- **Build boundaries**: PASS. Business logic remains under `pkg/build`, `pkg/oci`, `pkg/storage`, and related packages; no `pkg` dependency on `cmd`.
- **Verification commands**: PASS. Implementation must use `task format`, `task build`, lint prerequisites/lint, unit, scoped e2e, and integration commands. No raw Go tooling.
- **Generated/workflow files**: PASS. No `CHANGELOG.md`, release notes, or CLI reference changes are planned.

No constitution violations require justification.

## Research Summary

Detailed findings are in [research.md](./research.md). Key decisions:

1. Replace `sbomStep` and `vexStep` completely with mutable, non-buildable `SbomStage` and `VexStage` implementations attached to the image lifecycle.
2. Use explicit manifest/index subjects and resolve destination subjects after image copies.
3. Share idempotent propagation for SBOM and VEX across final, cache, and secondary-to-primary paths.
4. Preserve current checksum inputs and fallback artifact indexes during the migration, but implement them in the corresponding stages.
5. Validate registry-backed storage before stage execution when either feature is enabled.

## Design

### Stage integration

- Extend `pkg/build/stage` with stage names and constructors for `SbomStage` and `VexStage`, following the shape of `SignStage`.
- Move all behavior currently owned by `sbomStep` into `SbomStage`; remove `sbom_step.go` and its step-specific tests once callers are migrated.
- Move all behavior currently owned by `vexStep` into `VexStage`; remove `vex_step.go` and its step-specific tests once callers are migrated.
- Artifact stages must not mutate, rebuild, fetch, or store the image filesystem. Their `PrepareImage` path is a no-op; their `MutateImage` path operates on the associated OCI artifact and owns registry-side generation and publication.
- The stage's subject is the final image digest: for single-platform images this is the published image manifest digest; for multi-platform images SBOM uses each final platform manifest digest and VEX uses the final top-level image index digest. The artifact stage must never be treated as an image layer or as a replacement image.
- All registry reads, writes, copies, metadata operations, and artifact-related repository interaction from `SbomStage` and `VexStage` must use `StorageManager`. The manager selects primary, secondary, cache, or final `StagesStorage` according to the operation; direct registry client access and direct repository selection from the stages are prohibited.
- Extend `StorageManager` with the minimal artifact-oriented operations required by the stages and propagation. Implement the corresponding `StagesStorage` primitives only where needed to preserve fallback-index behavior: find/list attached artifacts, publish an OCI artifact for a final image digest, and copy attached artifacts between destination image descriptors. Implement these methods for every supported registry-backed storage implementation and keep local storage behavior explicit.
- Ensure stage dependencies include the parent image identity and all effective artifact inputs. SBOM dependencies include scanner, merge/GOST, signer, format version, and target platform. VEX dependencies include document content, parent identity, signer, and format version.
- Register the stages after the content-producing stage and before the lifecycle completes for applicable images. The registration must work for Stapel and Dockerfile image paths and for restored stages.
- Preserve stage cache behavior: a suitable artifact-bearing stage can be selected from primary/secondary storage; changed effective inputs produce a different stage identity.

### Artifact subjects and platform behavior

- Single-platform SBOM and VEX target the actual published image manifest digest.
- Multi-platform SBOM processing runs once per platform image and targets that platform manifest digest.
- Multi-platform VEX processing runs once for the image set and targets the top-level image index digest.
- Do not use the index digest as a platform SBOM subject or duplicate image-level VEX onto platform manifests.
- Keep existing signing behavior and include signer identity in cache identity. The signing and cache logic must live in the corresponding artifact stage, not in a retained step wrapper.

### Publication and propagation

- Consolidate artifact copying behind a kind-neutral `StorageManager` operation; it routes through the source/destination repository `StagesStorage` instances and copies every attached supported artifact from a source descriptor to a destination descriptor. This propagation helper is the only shared artifact operation; generation remains owned independently by `SbomStage` and `VexStage`.
- The propagation contract must carry the final image digest/descriptor explicitly and must never attach an artifact to the digest of the artifact stage itself.
- Use it after primary-to-final and primary-to-cache image copies, and when a suitable stage is copied from `--secondary-repo` into primary storage.
- Resolve the destination image descriptor/digest rather than assuming source and destination digests match.
- Skip local storage and identical repository addresses. Deduplicate by existing artifact identity/fallback index semantics.
- Return final-repository propagation errors to fail the build. Log cache-repository propagation failures and continue according to current best-effort behavior.
- Preserve concurrent fallback-index convergence guarantees and existing cleanup behavior.

### `AfterImages` simplification

- Remove SBOM/VEX generation calls from the post-build `AfterImages` path once stage execution provides equivalent coverage.
- Retain image metadata publication, final image copying, custom tag publication, telemetry, and report creation in `AfterImages`.
- Avoid retaining a second fallback/post-build convergence path that could regenerate or duplicate artifacts.

### Early validation

- Add validation in the earliest build phase before image work starts: if SBOM or VEX is enabled and stage storage is local-only, return an actionable registry-destination error.
- Keep builds with both features disabled unchanged.

## Project Structure

### Documentation

```text
specs/020-sbom-vex-build-stages/
├── spec.md
├── plan.md
├── research.md
├── data-model.md
├── quickstart.md
└── contracts/              # no external API contract required
```

### Expected implementation areas

```text
pkg/build/stage/
├── base.go                 # stage names and shared lifecycle metadata
├── sbom.go                 # SbomStage: generation, cache, signing, and publication
├── vex.go                  # VexStage: generation, cache, signing, and publication
└── sign.go                 # existing registry-side stage pattern

pkg/build/
├── build_phase.go          # stage registration, subject selection, propagation orchestration
└── ...

pkg/build/sbom_step.go and pkg/build/vex_step.go are removed after migration; their behavior is not retained behind compatibility wrappers.

pkg/storage/                  # StagesStorage interface and backend implementations for artifact stages
pkg/storage/manager/           # StorageManager routing across primary/secondary/cache/final and artifact propagation
pkg/oci/artifact/              # OCI artifact encoding and fallback-index support called by storage backends

Tests remain co-located under pkg/build and pkg/build/stage, with scenario coverage in:
test/e2e/sbom/
test/e2e/vex/
```

The exact internal helper split may vary, but the architectural boundary is fixed: no `sbomStep` or `vexStep` types/files remain after implementation, and `SbomStage`/`VexStage` are the sole lifecycle owners. No new package is required.

## Implementation Phases

### Phase 0: Research

Completed in [research.md](./research.md). No unresolved clarification remains. Existing checksum, platform, fallback-index, secondary-repository, and error-policy behavior was identified for reuse.

### Phase 1: Design

Completed in [data-model.md](./data-model.md) and [quickstart.md](./quickstart.md). No external interface contract is required because this is an internal build-pipeline change with unchanged CLI syntax and repository option semantics.

### Phase 2: Implementation preparation

The subsequent `/speckit-tasks` workflow should decompose at least these work items:

1. Implement `SbomStage` and `VexStage`, including stage identity, lifecycle integration, final image-digest association, OCI-artifact handling, cache checks, signing, publication, and `StagesStorage` access.
2. Migrate all SBOM behavior from `sbomStep` into `SbomStage`, then delete the step implementation and update callers/tests.
3. Migrate all VEX behavior from `vexStep` into `VexStage`, then delete the step implementation and update callers/tests.
4. Extend `StorageManager` with the minimal OCI-artifact operations, add any required `StagesStorage` backend primitives, and implement manager-routed artifact propagation for final, cache, and secondary-to-primary copies.
5. Move registry validation before image building and remove duplicate `AfterImages` convergence.
6. Add/adjust unit tests for stage flags, dependency identities, subjects, propagation, idempotency, and failure policies.
7. Extend e2e coverage for repository combinations, secondary restore, multi-platform placement, caching, and local-only rejection.
8. Verify cleanup/orphan behavior and unchanged builds without SBOM/VEX.

## Validation Plan

Use the repository-required sequence after implementation:

```text
task format
task build
task deps:install:golangci-lint
task lint
task test:unit
task test:e2e paths="./test/e2e/sbom/..." labelFilter="sbom"
task test:e2e paths="./test/e2e/vex/..." labelFilter="vex"
task test:integration
```

While iterating, use scoped `task lint:golangci-lint` and `task test:unit` paths for changed packages. Validate both positive and negative cases: successful registry-backed publication, local-only early failure, final failure, cache best effort, secondary restoration, repeated idempotent propagation, and correct platform subjects.

## Complexity Tracking

No constitution violations or new architectural projects are proposed. The only additional internal abstraction is a shared `StorageManager`-routed artifact propagation operation because SBOM-only propagation cannot satisfy VEX and secondary-to-primary requirements without duplication. The explicit distinction between ordinary image stages and OCI-artifact stages is required by the feature and is not an optional abstraction.
