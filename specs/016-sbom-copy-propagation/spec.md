# Feature Specification: SBOM Copy Propagation

**Feature Branch**: `feat/sbom/copy-to-final-repo`

**Created**: 2026-08-10

**Status**: migrated

**Input**: Reverse-engineered from working-tree implementation in `pkg/oci/artifact/copy.go`, `pkg/build/sbom_step.go`, `pkg/storage/`, `pkg/cleaning/`

## Project Context

**Delivery Kit** is a Go CLI tool for full-cycle CI/CD to Kubernetes, built on top of werf. SBOMs are stored as OCI artifacts (DSSE envelopes) attached to image manifests: the artifacts of a parent digest are listed in an OCI image index published under the canonical referrers tag `sha256-<hex>` in the same repository (see `specs/014-sbom-artifact-storage-model`).

werf copies stages between registry repositories in several flows: final images into the final repo (`--final-repo`), stages into cache repos (`--cache-repo`), and suitable stages from secondary read-only repos (`--secondary-repo`) into the primary. Before this feature, SBOM artifacts were published only into the stages repo (`--repo`) and never followed the stage anywhere, so `werf sbom get --repo <final-repo> --digest <digest>` failed even though the image itself was present there.

## User Scenarios & Testing *(mandatory)*

### User Story 1 — SBOM available in the final repo (Priority: P1)

A build with `--final-repo` publishes final images into the final repo. After SBOM generation, the SBOM of each final image is attached to the image's digest in the final repo, so consumers that only know the final repo can retrieve it with `werf sbom get --repo <final-repo> --digest <digest>`.

SBOM generation runs after the stage has already been copied into the final repo (`publishFinalImage` precedes `convergeSbomByImagesSets` in `BuildPhase.AfterImages`), so the artifact catches up in a dedicated post-converge step rather than during the stage copy.

**Covered by**: `pkg/build/sbom_step_propagate_test.go` — "should copy the SBOM into the final repo", "should fail when the final repo copy fails"; `test/e2e/sbom/final_repo_test.go` — "build with --final-repo → sbom get from the final repo by digest".

### User Story 2 — artifacts follow every stage copy (Priority: P1)

Whenever a stage manifest is copied between registry repositories — into the final repo, into a cache repo, or from a secondary repo into the primary — the artifacts attached to it in the source repo are attached to it in the destination too. Registry-level copies preserve the manifest digest; backend-mediated copies (secondary→primary) may change it, so artifacts are re-attached from their payload with the subject pointing at the destination digest rather than copied manifest-by-manifest.

**Covered by**: `pkg/oci/artifact/copy_test.go` — "should copy attached artifacts onto the same digest in another repo", "should copy attached artifacts onto a different parent digest".

### User Story 3 — best-effort propagation into cache repos (Priority: P2)

After SBOM generation, the SBOM is also propagated into each configured cache repo where the stage exists. Cache repos are best-effort mirrors: a propagation failure is logged as a warning and never fails the build, matching the failure semantics of stage copies into cache repos.

**Covered by**: `pkg/build/sbom_step_propagate_test.go` — "should copy the SBOM into cache repos", "should not fail when a cache repo is unreachable".

### User Story 4 — no stale artifact indexes after cleanup (Priority: P1)

`werf cleanup` and `werf purge` delete stages from the final repo. The `sha256-*` artifact indexes now written there must not be left orphaned: both commands run the orphaned-artifact deletion against the final stages storage in addition to the primary one.

**Covered by**: `pkg/cleaning/cleanup_test.go` — `deleteOrphanedArtifacts` table specs (same function drives both storages).

## Requirements *(mandatory)*

- **FR-001**: `CopyAttachedArtifacts(ctx, srcRepo, srcDigest, dstRepo, dstDigest)` copies every artifact-typed entry of the source fallback index onto the destination digest.
- **FR-002**: Artifacts are re-attached from payload via `OCIStore.Attach`, so the destination subject always points at the destination digest, and the source and destination digests may differ.
- **FR-003**: The copy is idempotent: an artifact already attached to the destination with the same identity (artifact type, image name, checksum, target platform) is skipped.
- **FR-004**: A missing source index (404) is a no-op, not an error — most stages carry no artifacts.
- **FR-005**: Index entries without an artifact type (descriptors written by go-containerregistry for subject-carrying manifests) are not copied; the werf-annotated entry for the same artifact is copied instead.
- **FR-006**: Registry credentials are resolved per host (`RemoteOptionsForHost`) separately for source and destination when no explicit options are given.
- **FR-007**: `RepoStagesStorage.CopyFromStorage` copies attached artifacts after the registry-level stage copy; a failure fails the copy.
- **FR-008**: `StorageManager.CopySuitableStageDescByDigest` copies attached artifacts after storing the stage in the destination, guarded against local storages on either side.
- **FR-009**: After SBOM converge, `sbomStep.PropagateArtifacts` copies the image's artifacts into the final repo (failure is fatal) and into each cache repo (failure is a warning), skipping local storages and the source repo itself.
- **FR-010**: `werf cleanup` and `werf purge` delete orphaned `sha256-*` artifact indexes from the final stages storage in addition to the primary one.

## Success Criteria *(mandatory)*

- **SC-001**: `werf sbom get --repo <final-repo> --digest <final-image-digest>` returns the SBOM after a build with `--final-repo`.
- **SC-002**: Running the propagation twice produces a single index entry per artifact in the destination (idempotency).
- **SC-003**: Artifacts of several images sharing one parent digest all reach the destination.
- **SC-004**: A stage copy of a stage without artifacts incurs one extra index GET and no writes.
- **SC-005**: After `werf cleanup`/`werf purge` removes a final-repo stage, its `sha256-*` index is removed by the same run's orphaned-artifact pass.

## Assumptions

- Registry-level stage copies (`DockerRegistry.CopyImage`) preserve the manifest digest; the artifact index tag in the destination is therefore the same as in the source for those flows.
- `OCIStore.Attach` requires the parent manifest to exist in the destination repo; every call site attaches only after the stage itself has been copied there.
- Cache repos are written to but never read from for artifact retrieval; propagation into them keeps artifacts and stages on the same lifecycle.
