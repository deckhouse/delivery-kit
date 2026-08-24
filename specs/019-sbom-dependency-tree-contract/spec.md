# Feature Specification: Выровнять контракт для всего дерева зависимостей при генерации SBOM

**Feature Branch**: `fix/sbom/import-dependency-skip`

**Created**: 2026-08-24

**Status**: Implemented

**Input**: Review of PR #268: add a spec for these changes, and — if possible — move this logic into a dedicated subpackage inside SBOM (`pkg/build/build_phase.go` L268-286 and L338-442).

## Project Context

**Delivery Kit** is a Go CLI tool for full-cycle CI/CD to Kubernetes. It is built on top of werf with Deckhouse Platform extensions. Key subsystems:

- **Build** (`pkg/build/`) — Container image building via Buildah
- **Deploy** (`pkg/deploy/`) — Kubernetes deployment via werf/nelm (Helm-based)
- **SBOM** (`pkg/sbom/`) — Software Bill of Materials generation and validation
- **Cleanup** (`pkg/cleaning/`) — Container registry cleanup policies
- **Signature** (`pkg/signature/`) — Container image signing and verification
- **Docker Registry** (`pkg/docker_registry/`) — OCI registry operations
- **Config** (`pkg/config/`) — werf.yaml configuration parsing

## Background

Spec [017](../017-sbom-converge-failure-semantics/spec.md) established the failure contract of SBOM converge: an image whose PURL enrichment fails does not get its SBOM published, its dependents are skipped with the real root cause instead of the misleading "rebuild it with SBOM generation enabled", and the aggregated report is emitted on every exit path.

That contract was implemented for **half** the dependency tree. An image's SBOM merges the SBOMs of two kinds of dependencies:

- its base image (`fromImage`) — covered by the skip logic;
- its internal import sources (`import:`) — **not covered**.

On the operator-helm build (werf 2.77.0-dk.3) this surfaced immediately after the 017 release: an image importing from a skipped `nelm-source-controller-artifact` was not skipped, went into converge, hit the missing artifact in the import path and aborted the build — with exactly the misleading message 017 had removed from the base path.

A second, smaller asymmetry: the missing-SBOM error is produced by a single code path serving both dependency kinds, but called every image "the base image", so a project importing from an SBOM-less image was told to rebuild a base image it never declared.

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Import dependents are skipped like base dependents (Priority: P1)

A CI user builds a project where image `c` imports from image `b`, and PURL enrichment fails for `b` (or for `b`'s own base). Today the build aborts on `c` with the misleading advice to rebuild the base image with SBOM generation enabled. Instead `c` must be skipped with `b`'s real cause, and the build must reach the aggregated report like it does for `fromImage` dependents.

**Why this priority**: This is the production failure observed in CI directly after the 017 release; it reinstates the exact class of bug 017 was meant to remove.

**Independent Test**: Build a project with `c` importing from `b` against a resolver failing one of `b`'s packages; verify `c` is reported as skipped with `b`'s cause and that no "rebuild it with SBOM generation enabled" advice appears.

**Acceptance Scenarios**:

1. **Given** image `c` imports from image `b` and `b`'s enrichment failed in this run, **When** SBOM converge reaches `c`, **Then** `c` is skipped and appears in the aggregated report with `b`'s enrichment error as the cause.
2. **Given** a mixed chain where `a` fails, `b` is skipped because it is built `fromImage: a`, and `c` imports from `b`, **When** converge reaches `c`, **Then** the reported root cause is `a`'s enrichment error, not `b`.
3. **Given** an image importing from an **external** image (not built by this run) that has no SBOM attached, **When** converge reaches it, **Then** the existing "attach an SBOM / rebuild with SBOM generation enabled" guidance is still produced — that image is outside this run and the advice is actionable for its owner.

---

### User Story 2 - The advice does not misname the dependency kind (Priority: P2)

A user importing from an image without an attached SBOM is told to fix **that image**, not "the base image" they never declared as a base.

**Why this priority**: Wrong terminology sends users looking for a non-existent `from:` directive; cheap to fix and it removes the last base-only assumption from the shared error path.

**Independent Test**: Trigger the missing-SBOM error and inspect the text: it names the image and asks to rebuild it, with no claim that the image is a base.

**Acceptance Scenarios**:

1. **Given** an image without an attached SBOM used as an import source, **When** the missing-SBOM error is produced, **Then** it names that image and does not call it a base image.
2. **Given** the same error, **When** it is produced for a base image, **Then** the guidance and the legacy multi-platform hint are unchanged in meaning.

---

### User Story 3 - The failure contract lives in one cohesive place (Priority: P3)

A developer changing SBOM failure semantics — adding a dependency kind, a failure class, or adjusting the report — works against one unit with its own tests, instead of loose functions inside the 1900-line build-phase file whose tests can only run as part of the build package.

**Why this priority**: Requested during review of this change and it addresses the root cause of the P1 bug: the "dependency" concept was implicit and half-implemented because it had no home. Behaviour-neutral, so it ranks below the two user-visible stories.

**Independent Test**: The failure-semantics tests run scoped to the new package alone, without constructing a build phase or conveyor, and the build output for every failure mode is unchanged.

**Acceptance Scenarios**:

1. **Given** the extracted package, **When** its tests run scoped to it, **Then** they cover failure records, dependency collection, skip lookup, report rendering and resolver-unavailable canonicalization, and pass without build-phase fixtures.
2. **Given** each failure mode (content failure, skipped dependent, breaker trip, clean build), **When** a build runs before and after the extraction, **Then** console output and exit code are identical.
3. **Given** the build phase after extraction, **When** searching it for the failure-semantics functions, **Then** none remain there and none are duplicated.

---

### Edge Cases

- Transitive chains mixing both dependency kinds (base → import → base) report the original failing image, not an intermediate skipped one.
- An image whose base **and** import source both failed: one skip record, one cause; the report lists the image once.
- Multiplatform images: records and skip decisions stay keyed by image name, as established in 017.
- An image with only external imports and no base: never skipped by this logic.
- A hard non-PURL error coexisting with accumulated failures: the report is still emitted, the hard error stays terminal.
- The extraction must preserve safety under the existing parallelism: the failure store is written by parallel workers and read by consumers.

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: The set of dependencies whose missing SBOM makes an image's own SBOM ungenerable MUST include both the base image and internal import sources.
- **FR-002**: An image depending — through either kind — on an image recorded as "SBOM not generated in this run" MUST be skipped before converge, with the root cause propagated transitively across mixed chains.
- **FR-003**: Skipped images MUST appear in the aggregated report with their cause and MUST NOT produce the missing-SBOM advice.
- **FR-004**: External import sources MUST NOT participate in skip logic: they are not produced by this run, so the existing missing-SBOM guidance stays correct and actionable for them.
- **FR-005**: Both dependency kinds MUST be served by one shared mechanism — collection, lookup and cause construction — so that a change to failure semantics applies to both without a second edit.
- **FR-006**: The skip cause wording MUST be dependency-kind neutral, because the root of a chain reached through an import is not necessarily a base image of the skipped one.
- **FR-007**: The missing-SBOM error MUST NOT assert that the image is a base image; it MUST name the image and keep the existing guidance and legacy multi-platform hint.
- **FR-008**: The failure-semantics logic — failure records, error classification, dependency collection, skip lookup, cause construction, aggregated report building, resolver-unavailable canonicalization, the resolver help hint, and ownership of the failure store and breaker lifetime — MUST reside in a dedicated package under the SBOM subsystem.
- **FR-009**: The build phase MUST retain only orchestration and MUST NOT re-implement any part of the failure contract.
- **FR-010**: Failure-semantics tests MUST live with that package and MUST NOT require a build-phase or conveyor instance.
- **FR-011**: The extraction MUST NOT change behaviour: user-facing output, error identities, retry policy, breaker threshold and failure classification rules stay as they are.
- **FR-012**: No new configuration, CLI flags, or environment variables are introduced.

### Key Entities

- **SBOM dependency**: an in-project image whose SBOM is merged into another image's SBOM — its base image or an internal import source.
- **Failure record**: per image name — either a direct enrichment failure carrying component details, or a skip record pointing at the root-cause image.
- **Aggregated report**: hierarchical rendering of all failure records, emitted on every converge exit path.
- **Resolver availability state**: per-build circuit-breaker state whose canonical error terminates the build.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: In a project where an image imports from an image with failing enrichment, the build reports the importing image as skipped with the real cause and produces zero occurrences of the misleading rebuild advice.
- **SC-002**: A transitive chain mixing base and import dependencies reports the originally failing image as the cause at every level.
- **SC-003**: The missing-SBOM error contains no claim that the named image is a base image.
- **SC-004**: Adding a new dependency kind requires a change in exactly one place for both existing consumers of the contract.
- **SC-005**: For each failure mode — content failure, skipped dependent, breaker trip, clean build — console output and exit code are identical before and after the extraction.
- **SC-006**: The failure-semantics test suite runs scoped to its own package and passes with no references to build-phase types.

## Assumptions

- Image sets are already ordered by both dependency kinds, so any dependency's failure record exists before its consumer is processed; the ordering itself is out of scope.
- The name of the extracted package and its exported signatures are implementation decisions taken during planning; the spec fixes only where the logic lives and what it guarantees.
- Current behaviour is the specification for the extraction: where implementation and documentation disagree, the implementation wins and the discrepancy is reported rather than silently changed.
- Behavioural changes beyond the two user-visible fixes above — new failure classes, report format changes, policy for `empty url` / unknown-kind resolver answers — are out of scope and belong to follow-up features.
- The wiki page describing the aggregation strategy is updated where it names the contract or code locations.
- End-to-end confirmation requires a linux/amd64 host; the SBOM e2e suite cannot run on the development host.
