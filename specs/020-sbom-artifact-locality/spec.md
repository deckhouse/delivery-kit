# Feature Specification: Artifact Locality

**Feature Branch**: `fix/sbom/artifact-locality`

**Created**: 2026-09-01

**Status**: Draft

**Input**: User description: "нужно создать и закрепить жесткий контракт — sbom всегда прикрепляется к образу в тот реджистри, в который кладется сам образ, по схеме хранения, при любом копировании, перенесении образов/стадий/etc, вместе с ним переезжает и sbom"

## Project Context

**Delivery Kit** is a Go CLI tool for full-cycle CI/CD to Kubernetes, built on top of werf with Deckhouse Platform extensions. Subsystems touched by this feature:

- **Build** (`pkg/build/`) — SBOM and VEX convergence during image build
- **OCI artifacts** (`pkg/oci/artifact/`) — cosign-compatible artifact storage: fallback tags, subject, DSSE
- **Storage** (`pkg/storage/`, `pkg/storage/manager/`) — stage copies between repositories, meta repo
- **Stages transfer** (`pkg/build/stages/`) — `werf stages copy`
- **Bundles** (`pkg/deploy/bundles/`) — bundle copy between registries
- **Cleanup** (`pkg/cleaning/`) — orphaned artifact collection
- **CLI** (`cmd/werf/sbom/`, `cmd/werf/attest/`) — artifact retrieval

The artifact storage model itself is defined in `specs/014-sbom-artifact-storage-model`: artifacts of a parent digest are listed in an OCI image index published under the canonical referrers tag `sha256-<hex>` in the same repository as the parent. This feature does not change that model; it makes the model hold everywhere.

## Problem

The repository an SBOM lands in is currently decided by whatever descriptor the build phase happens to hold at convergence time, and copying an image between repositories carries its artifacts only on some code paths.

**The SBOM is written to the final repo and nowhere else.** `publishFinalImage` overwrites the image's content tag descriptor with the final repo descriptor (`pkg/build/build_phase.go:530`), and SBOM convergence resolves its target through `GetLastNonEmptyStageDesc()`, which prefers that descriptor (`pkg/build/image/image.go:347-350`). With `--final-repo`, a single-platform build therefore attaches the SBOM to the image in the final repo, and `werf sbom get --repo <stages-repo>` returns nothing. Verified in CI: `test/e2e/sbom/final_repo_cleanup_test.go` reads the SBOM from the final repo successfully and fails to read it from the stages repo, and the build log contains no artifact copy step.

**Dependent builds fail.** A project where one final image is the base of another (`fromImage`), built with `--final-repo` against a clean registry, does not build: the base image's SBOM is written to the final repo, the dependent image's base-SBOM lookup reads the stages repo, and the build fails with advice to enable SBOM generation — which is already enabled. Reproduced locally on a scratch-based two-image project; the `import` dependency kind survives because its lookup happens to ride the same descriptor as convergence (Q2).

**Where the SBOM ends up depends on build history.** `RepoStagesStorage.CopyFromStorage` copies attached artifacts (`pkg/storage/repo_stages_storage.go:977`), but the stage is copied into the final repo before the SBOM exists, and the copy short-circuits when the stage is already present in the destination (`:962`). A first build with `--final-repo` leaves one copy in the final repo; a build without `--final-repo` followed by one with it leaves copies in both. The same command produces different registry states.

For a multi-platform image the artifacts are copied onto the wrong digest, and collide there. SBOM convergence attaches one SBOM per platform manifest in the stages repo, as `specs/016-sbom-multiplatform-per-platform` requires, and propagation then copies each of them onto the *index* digest in the final repo, because `finalStageDescForImage` (`pkg/build/build_phase.go:443-444`) resolves a single descriptor — the index — for the whole image. Retrieval goes the other way: `werf sbom get` against an index digest requires `--platform`, resolves it to the platform manifest digest (`pkg/oci/artifact/platform.go:57-83`, `matchPlatformDigest:178-201`) and reads the artifact from there, where nothing was attached; without `--platform` it refuses to proceed at all. Worse, the copies collide: both platform SBOMs target the same parent digest, and the fallback index replaces entries by artifact type and image name — platform is not part of the key — so the second platform's copy displaces the first. The final repo ends up with one platform's SBOM missing entirely and the other attached to a digest no retrieval path resolves, even though the build report points the user at exactly that index digest. Confirmed by registry inspection of a local reproduction (Q3).

Several transfer paths never carry artifacts at all: `werf stages copy` (`pkg/build/stages/remote_storage.go:83,116`), meta repo migration (`pkg/storage/meta_repo_marker.go:399`), bundle copy (`pkg/deploy/bundles/remote_bundle.go:192`), and `werf export` (`pkg/storage/repo_stages_storage.go:150`, out of scope here). For a multi-platform image, `CopyFromStorage` copies the artifacts of the index digest only, so per-platform SBOMs attached to platform manifest digests do not follow the index into another repository.

This also contradicts `specs/016-sbom-copy-propagation` (US1, FR-009), which specifies that the SBOM is generated against the stages repo and propagated into the final repo afterwards.

## User Scenarios & Testing *(mandatory)*

### User Story 1 — The artifacts are where the image is (Priority: P1)

Whoever can pull an image built by werf can read its artifacts — SBOM, VEX, attestations — from the same repository, using only the image reference. This holds for the stages repo, the final repo, and every cache repo the stage was placed in, and it does not depend on which flags the build used or on what was built before.

**Why this priority**: this is the contract. Everything else in this feature is a path that has to satisfy it.

**Independent Test**: build a project with `--final-repo` against a clean registry, then run `werf sbom get` against each repository that holds the image.

**Acceptance Scenarios**:

1. **Given** a build with `--final-repo` on a clean registry, **When** it completes, **Then** `werf sbom get --repo <stages-repo> --tag <stage-tag>` and `werf sbom get --repo <final-repo> --digest <final-digest>` both return the SBOM of that image.
2. **Given** the same project built without `--final-repo` first and with it afterwards, **When** the second build completes, **Then** both repositories hold the SBOM, identical to the single-build case.
3. **Given** a build with `--cache-repo`, **When** it completes, **Then** the SBOM is retrievable from the cache repo against the digest the stage has there.
4. **Given** any of the above, **When** the artifact index of the image's digest in each repository is inspected, **Then** the artifact is attached there with its OCI subject pointing at that digest.

---

### User Story 2 — Artifacts follow every stage copy (Priority: P1)

Copying a stage between repositories carries the artifacts attached to it, regardless of which copy path is taken and regardless of whether the destination already holds the stage manifest.

**Why this priority**: the contract cannot rest on convergence alone — an image reaches most repositories by being copied, not by being built there.

**Independent Test**: attach an SBOM to a stage, copy the stage through each path, then read the SBOM from the destination.

**Acceptance Scenarios**:

1. **Given** a stage with an attached SBOM, **When** it is copied into the final repo or a cache repo, or from a secondary repo into the primary with the digest preserved, **Then** the SBOM is attached to the stage in the destination.
2. **Given** a destination that already holds the stage manifest but not its artifacts, **When** the copy runs, **Then** the artifacts are copied even though the manifest copy is skipped.
3. **Given** a backend-mediated copy from a secondary repo where the destination digest differs from the source digest, **When** the build completes, **Then** the image in the primary carries freshly converged SBOM and VEX under the new digest, artifacts werf cannot regenerate are reported as left behind, and nothing is attached whose payload names a different digest.
4. **Given** a stage with no attached artifacts, **When** it is copied, **Then** the copy succeeds and attaches nothing.
5. **Given** a cache repo that was unreachable when the artifacts were first propagated, **When** a later build runs with that cache repo reachable, **Then** the missing artifacts are attached to the stages already present there, and the earlier build was not failed by the outage.

---

### User Story 3 — `werf stages copy` carries artifacts (Priority: P2)

Transferring a project's stages into another registry with `werf stages copy` brings the SBOMs along, so the destination registry is a complete replica rather than images without provenance.

**Why this priority**: this is the command used to move a project between registries, including into air-gapped environments — exactly the case where re-generating an SBOM is impossible.

**Independent Test**: build a project with SBOM enabled, `werf stages copy` into a second registry, read the SBOM from the second registry.

**Acceptance Scenarios**:

1. **Given** a project whose stages carry SBOMs, **When** `werf stages copy` transfers them to another registry, **Then** each copied stage has its SBOM attached in the destination.

---

### User Story 4 — Multi-platform images keep per-platform SBOMs (Priority: P2)

Copying a multi-platform image into another repository brings the SBOM of every platform manifest, not only whatever is attached to the index.

**Why this priority**: `specs/016-sbom-multiplatform-per-platform` places SBOMs on platform manifest digests and explicitly not on the index digest, so an index-only copy loses every SBOM the image has.

**Independent Test**: build a two-platform image with `--final-repo`, then read the SBOM for each platform from the final repo.

**Acceptance Scenarios**:

1. **Given** a two-platform build with `--final-repo`, **When** it completes, **Then** each platform manifest digest in the final repo has its own SBOM attached, with its OCI subject equal to that platform manifest digest.
2. **Given** the same build, **When** the index digest's fallback tag in the final repo is inspected, **Then** no SBOM is attached to it.
3. **Given** the same build, **When** `werf sbom get --repo <final-repo> --digest <index-digest> --platform <platform>` runs, **Then** it returns that platform's SBOM.
4. **Given** the digest reported for that image in the build report, **When** the user passes it to `werf sbom get` together with a platform, **Then** the SBOM is returned — the reported digest is the entry point users actually have.

---

### User Story 5 — Images that depend on each other build with `--final-repo` (Priority: P1)

A project where one image is built on top of another image of the same project builds successfully with `--final-repo` and SBOM generation enabled, and every image gets an SBOM that includes the packages inherited from its base.

**Why this priority**: the base image SBOM is merged into the dependent image's SBOM, so resolving it is a build-time dependency, not a retrieval concern. If the base SBOM cannot be found, the build fails with a message telling the user to rebuild with SBOM generation enabled — advice that cannot help, because generation is already enabled and the SBOM already exists elsewhere.

**Independent Test**: build a two-image project where the second image uses the first as its base, with `--final-repo`, against a clean registry.

**Acceptance Scenarios**:

1. **Given** a project with `image: base` and `image: app` using `fromImage: base`, SBOM enabled, **When** it is built with `--final-repo` against a clean registry, **Then** the build succeeds.
2. **Given** that build, **When** the SBOM of `app` is read, **Then** it contains the packages contributed by `base`.
3. **Given** a project where one image imports files from another, **When** it is built with `--final-repo`, **Then** the same holds for the importing image.
4. **Given** any of the above, **When** the build is repeated, **Then** it still succeeds and reuses the cached SBOMs rather than regenerating them.

---

### Edge Cases

- The destination repository already holds the artifact with the same identity: the copy is a no-op, not a duplicate and not an error.
- The source stage has no artifacts: every copy path succeeds and attaches nothing; a missing artifact index is not an error.
- A cache repo is unreachable during propagation: the build is not failed and the failure is reported as a warning, and the gap is closed by the next build that reaches the cache repo. The final repo and the stages repo are not best-effort.
- The registry rejects the artifact push mid-copy: on paths where artifact placement is not best-effort, the copy is reported as failed rather than leaving the image silently without artifacts.
- The same stage is copied concurrently by parallel workers: the artifact index ends in a consistent state without lost entries.
- An image whose base image is another final image of the same project: the base SBOM lookup must resolve in a repository that actually holds it.
- A build resolved entirely from cache, where no stage was rebuilt: the artifacts still reach every repository that receives the stage.
- Cleanup runs against a repository holding artifacts whose parent manifests are gone: they are collected as orphans, unchanged from today.

## Requirements *(mandatory)*

### Functional Requirements

#### The contract

The contract is stated over pairs of a repository and a subject digest, not over image names: an image has different digests in different repositories, and a multi-platform image has one subject digest per platform manifest. It applies to registry-backed storages only: the local storage and the archive format have no notion of the fallback-tag model, and transfers through them are out of scope here (see Out of Scope).

The invariant is required to hold once an operation has completed successfully. Placing an image and attaching its artifacts are separate registry operations with no transaction between them, so an interrupted or failed run can leave an image without its artifacts; FR-016 makes a repeated run repair that state rather than skip it.

Cache repos hold the same invariant, but reach it later. Copying a stage into a cache repo is best-effort today — an unreachable cache repo produces a warning and the build continues — and this feature does not make a cache repo a prerequisite for a successful build. Instead the gap is required to be temporary: the first later build that reaches the cache repo attaches the missing artifacts to stages already present there. A cache repo is an ordinary registry that images can be pulled from, so an image left there without provenance is not acceptable as a permanent state; failing a build because a cache repo was briefly unavailable is not acceptable either.

- **FR-001**: If a repository holds a manifest with digest D, and an artifact describing D exists in any repository, then that artifact MUST be present in this repository under the fallback tag of D.
- **FR-002**: An artifact MUST be attached with its OCI subject set to the digest the described image has in that same repository. The in-toto subject inside a DSSE payload is not rewritten: it is covered by the signature and records provenance, not location (see Assumptions).
- **FR-003**: For the stages repo and the final repo, FR-001 MUST hold when a build completes successfully. For cache repos it MUST hold no later than the first subsequent successful build that reaches the cache repo.
- **FR-004**: The set of repositories satisfying FR-001 MUST NOT depend on build order, on cache state, or on which stages were rebuilt in that run.
- **FR-005**: An operation MUST NOT leave an artifact attached to a digest whose manifest that operation removed or never placed. Artifacts orphaned by earlier operations are collected by cleanup under FR-021.

#### Convergence

- **FR-006**: Artifact convergence — SBOM and VEX alike — MUST target the repository in which the image was built — the stages repo — regardless of which other repositories the image is published to in the same run. The convergence target MUST be resolved independently of the descriptor used for publication and reporting, so that publishing an image elsewhere cannot move where its artifacts are written.
- **FR-007**: The lookup that decides whether an artifact has to be regenerated or republished MUST be performed against the same repository the convergence targets, so that publishing to additional repositories never triggers regeneration.
- **FR-008**: The base image and imported image SBOM lookups MUST use the same target resolution as artifact convergence, so the reader and the writer can never disagree about the repository and digest. Today both sides ride the content tag descriptor (`SetupBaseImage` wraps the base image's `contentTagDesc`, convergence writes through `GetLastNonEmptyStageDesc`), which is why dependent builds with `--final-repo` work despite the misplaced artifacts — the system is consistently wrong. A fix that moves the convergence target without moving the lookup breaks dependent builds that are green today.

#### Copy paths

- **FR-009**: Copying a stage into the final repo MUST carry its attached artifacts.
- **FR-010**: Copying a stage into a cache repo MUST carry its attached artifacts. A failure is a warning, not a build failure, and the missing artifacts MUST be attached by a later build under FR-016.
- **FR-011**: Copying a suitable stage from a secondary repo into the primary is backend-mediated and does not guarantee digest preservation; the decision is made per copy, on the digests at hand. If the destination digest equals the source digest, the attached artifacts MUST be carried, byte-identical. If it differs, they MUST NOT be carried — a statement about the source digest is not a statement about the destination digest: werf-generated artifacts are regenerated by convergence in the same run (the cache lookup is scoped to repository and digest, so it misses in the primary), and artifacts werf cannot regenerate, such as user-signed attestations, are left behind with a warning naming them.
- **FR-012**: `werf stages copy` MUST carry the attached artifacts of every stage it transfers between registries.
- **FR-013**: Meta repo migration and detachment move only metadata records — managed-image marks, image metadata, cleanup and custom-tag records — which carry no attached artifacts, so they satisfy the contract with no change. Should they ever start moving image manifests, those MUST carry their artifacts.
- **FR-014**: Bundle copy between registries MUST carry the attached artifacts of the images it copies.
- **FR-015**: A copy path MUST carry artifacts even when the destination already holds the image manifest and the manifest copy is skipped.
- **FR-016**: Repeating an operation MUST repair a destination that holds the image without its artifacts, so that a retry converges on the invariant rather than short-circuiting on the present manifest.
- **FR-017**: Copying an image index MUST carry the artifacts of every manifest it references, in addition to the artifacts of the index digest itself. An artifact MUST be attached to the digest of what it describes: an SBOM describing a platform manifest belongs on that platform manifest's digest and MUST NOT be moved onto the index digest, while an artifact describing the image as a whole — as VEX does for a multi-platform image — belongs on the index digest.
- **FR-018**: Artifact copying MUST be idempotent: an artifact already present at the destination with the same identity is skipped.
- **FR-019**: A copy that placed the image but failed to place its artifacts MUST be reported as a failure on the paths where artifact placement is not best-effort.

#### Retrieval and cleanup

- **FR-020**: `werf sbom get`, `werf attest get`, `werf attest ls` and `werf attest verify` MUST return the artifact when pointed at any repository that holds the image.
- **FR-021**: Cleanup and purge MUST continue to collect artifact indexes whose parent manifest no longer exists, in every repository they operate on.
- **FR-022**: Cleanup MUST NOT delete an artifact whose parent manifest is still present in that repository.

#### Scope of "artifact"

- **FR-023**: The contract applies to every artifact attached through the fallback-tag model — SBOM, VEX, attestations and signatures — not to SBOM alone. They share one storage mechanism, one copy primitive and one convergence target resolution, so restricting the contract to SBOM would require filtering by artifact type: more code, to leave the remaining kinds diverging between repositories.

### Key Entities

- **Attached artifact**: an OCI artifact describing an image — SBOM, VEX, attestation, signature — identified by its artifact type, image name, checksum and target platform, and addressed through the fallback tag of its subject digest.
- **Artifact index**: the OCI image index published under `sha256-<hex>` listing the artifacts attached to that digest in that repository.
- **Copy path**: any operation placing an existing image or stage into a registry-backed repository it was not built in — final repo publication, cache repo propagation, secondary-to-primary resolution, `werf stages copy`, meta repo migration, bundle copy.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: For every repository that holds an image after any build or copy operation, `werf sbom get` and `werf attest ls` against that repository return the image's artifacts.
- **SC-002**: Building the same project on a clean registry with `--final-repo`, and building it first without and then with `--final-repo`, produce the same set of repositories holding the SBOM.
- **SC-003**: A two-platform image copied into another repository has one SBOM per platform manifest there, and none on the index digest.
- **SC-004**: A project transferred to a second registry with `werf stages copy` yields the same `werf sbom get` and `werf attest ls` results in the destination as in the source.
- **SC-005**: Repeated builds and repeated copies do not create duplicate artifact entries.
- **SC-006**: `werf cleanup` followed by a second `werf cleanup` leaves the SBOM of every in-use image intact in every repository holding it, and removes artifacts whose parent image is gone.
- **SC-007**: A build of a project whose images depend on each other through `fromImage` or `import`, with `--final-repo`, completes successfully with SBOMs for every image.
- **SC-008**: No copy path in scope places an image in a repository without its artifacts; this is demonstrated by a test per path rather than by inspection.
- **SC-009**: A build during which a cache repo is unreachable succeeds, and the next build with that cache repo reachable leaves it satisfying the invariant.

## Assumptions

- The artifact storage model of `specs/014-sbom-artifact-storage-model` is unchanged: this feature makes the model hold on every path, it does not redefine addressing.
- An artifact carries two subjects with different roles. The OCI subject binds the artifact to a manifest in a repository; werf rewrites it on every copy, and the contract is stated over it. The in-toto subject inside a DSSE payload records what the generator described — repository name and digest at generation time — and is covered by the signature, so copying MUST NOT rewrite it: a payload that changes on copy would invalidate the signature, and rewriting an unsigned one would forge the statement. No werf consumer requires the in-toto subject to match the artifact's current location (`UnwrapInTotoStatement` reads only the predicate; `attest verify` checks the DSSE signature), and none may start to.
- Per-platform attachment from `specs/016-sbom-multiplatform-per-platform` is unchanged: SBOMs belong on platform manifest digests, never on the index digest.
- Registry-level image copies preserve manifest digests, and for an image index this extends to the platform manifests it references, so carrying per-platform artifacts is a digest-to-digest copy that needs no re-attachment or subject rewrite. Backend-mediated copies (secondary to primary) do not guarantee digest preservation; whether the digest survived is known at copy time and drives FR-011.
- Cache repos remain best-effort at the level of a single build: a build is never failed because a cache repo could not be written to, matching how copying the stage itself already behaves. They are not exempt from the contract: a cache repo is an ordinary registry that images can be pulled from, and builds write stages into it.
- Cache repos do not supply stages to the primary repository: stage IDs are always listed from the primary storage, and cache repos only accelerate fetching descriptors and layers. Reusing stages built elsewhere is what `--secondary-repo` does, and that path already carries artifacts.
- Cleanup semantics are not changed by this feature beyond continuing to hold for the repositories that now reliably carry artifacts.
- The number of registry round trips grows on copy paths that previously copied nothing; this is accepted as the cost of the contract.

## Root Cause

The single-copy state was produced by two regressions inside one branch, both merged to `main` by PR #225 (`da68c2764`).

The first is `55dc5ea4b` ("feat(build, tagging): add content-based tag independent of build"): `publishFinalImage` stopped storing the final repo descriptor where SBOM propagation reads it (`SetFinalStageDesc` was replaced by `SetContentTagDesc`), so `PropagateArtifacts` began receiving nil for single-platform images and the copy into the final repo silently stopped happening. From that commit on there was one copy in the stages repo, and `werf sbom get --repo <final-repo>` was broken — the exact capability `specs/016-sbom-copy-propagation` was written for.

The second, `a891ed411` ("fix(build): handle cached image descriptors safely"), moved the single copy rather than restoring the second one — and is an unintended side effect, not a deliberate change of the storage location. It fixed a nil-pointer panic on cache-hit images, where `contentTagDesc` is set but `lastNonEmptyStage` is not. Its own assessment (`.specify/bugs/e2e-sbom-vex-nil-pointer/assessment.md`) states the goal as preserving existing behavior — "Preserve the existing multi-platform behavior that selects the index descriptor for VEX/SBOM artifacts" — and describes the content tag descriptor as the *fallback* for the cache-hit case: "For a cache-hit image it should use `contentTagDesc`; otherwise it should obtain the descriptor from `lastNonEmptyStage`". The implementation inverted that priority: `GetLastNonEmptyStageDesc` (`pkg/build/image/image.go:347-350`) prefers `contentTagDesc` unconditionally, copying the access pattern of the pre-existing `GetLastNonEmptyStageImageInfo`.

The underlying defect is that one accessor answers two different questions. `contentTagDesc` means "the descriptor of the published image" — which `publishFinalImage` (`pkg/build/build_phase.go:530`) sets to the final repo descriptor, and which the build report and content-based tagging legitimately need. Artifact convergence needs a different thing: the descriptor of the image being scanned and described, which is always the one in the repository the image was built in. While SBOM convergence read the stage descriptor directly the two never diverged; routing it through the shared accessor silently moved the storage location.

This feature therefore restores the model of `specs/016-sbom-copy-propagation` and extends it, rather than superseding it. Restoring it includes reviving the propagation step itself, dead since `55dc5ea4b`, not only re-pointing the convergence target.

## Out of Scope

These are deliberately left for separate work; the contract is not claimed to hold for them.

- **`werf export`**: the exported image is mutated on the way out and therefore has a new digest, and its destination is outside werf's own repository layout. Carrying artifacts there means re-attaching them to a digest werf does not otherwise track, which is a different problem from keeping build-time repositories consistent.
- **Transfers through the local storage and through an archive**: `werf stages copy` via a tar archive, and copies out of the local storage, have no fallback-tag model to carry. Making artifacts survive them requires extending the archive format; deciding between that and telling the user plainly that artifacts are not carried is separate work.
- **Backfilling images published by earlier versions**: images already in a registry keep whatever placement they were built with. The contract is forward-only, effective from the next build. No repair pass is required.

## Open Questions

- **Q2**: RESOLVED by local reproduction — the answer is the opposite of what CI run 33604003423 suggested. A clean-registry build of a `fromImage`-dependent project with `--final-repo` FAILS: the base image's SBOM is converged into the final repo while the dependent image's lookup reads the stages repo reference, and the build dies with "must have an SBOM artifact attached; rebuild with SBOM generation enabled". The original CI green was a false negative: the fixture's base image inherited the `io.deckhouse.internal.builder` label from the trusted builder base, and `WERF_E2E_ALLOW_LOCAL_BUILDER_IMAGES` degraded the failed lookup into a silent skip, while the asserted base packages appeared in the dependent SBOM via the filesystem scan rather than the merge. The tests were rewritten on scratch-based fixtures with no such escape and now falsify the lookup: `fromImage` entries fail on current main, `import` entries pass — the import-side lookup happens to resolve through the same descriptor as convergence, the base-side one does not. Both are pinned by US5 tests.
- **Q3**: RESOLVED by local reproduction with registry inspection (and CI run 33604003423). The stages repo is correct: each platform manifest digest carries its own SBOM under its fallback tag. The final repo is broken twice over. First, both per-platform SBOMs are copied onto the fallback tag of the *index* digest, where no retrieval path looks. Second, only one survives: both copies target the same parent digest, and the fallback index replace key — artifact type plus image name, platform not included — makes the second platform's copy displace the first. So in the final repo one platform's SBOM is physically absent and the other is unreachable. Repair is a re-propagation from the stages repo, which holds both intact. The earlier claim in this question that the stages repo was also broken misread the CI failure message, which does not name the repository; the failing fetch was against the final repo.
