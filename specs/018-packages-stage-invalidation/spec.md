# Feature Specification: Reliable packages stage rebuilds for file-based package ecosystems

**Feature Branch**: `fix/sbom/warn-missing-stage-deps`

**Created**: 2026-08-21

**Status**: Implemented

**Input**: User description: "With a file-based packages directive (go-mod, python-pip, rust-cargo, javascript-*, lua-rock), changing the spec/lock file contents never rebuilds the packages stage unless the files are tracked via git.stageDependencies.packages: installed dependencies silently go stale while the SBOM keeps reporting the updated files. Protect users from this trap."

## Project Context

**Delivery Kit** is a Go CLI tool for full-cycle CI/CD to Kubernetes. It is built on top of werf with Deckhouse Platform extensions. Key subsystems:

- **Build** (`pkg/build/`) — Container image building via Buildah
- **Deploy** (`pkg/deploy/`) — Kubernetes deployment via werf/nelm (Helm-based)
- **SBOM** (`pkg/sbom/`) — Software Bill of Materials generation and validation
- **Cleanup** (`pkg/cleaning/`) — Container registry cleanup policies
- **Signature** (`pkg/signature/`) — Container image signing and verification
- **Docker Registry** (`pkg/docker_registry/`) — OCI registry operations
- **Config** (`pkg/config/`) — werf.yaml configuration parsing

## Problem

The packages stage digest is derived from the generated install command plus the checksum of files listed in `git.stageDependencies.packages`. For file-based ecosystems the install command contains only paths (e.g. `cd "/app" && go mod download`), so:

- Without `stageDependencies.packages`, a change to spec/lock file contents (e.g. a dependency bump in `go.mod`) leaves the stage digest intact and the install command is never re-run.
- The updated spec/lock files still reach the final image through the git patch, and the SBOM cataloger reads them from the image — so the SBOM reports packages that were never actually installed.
- The result is a silently stale image with a lying SBOM: a supply-chain artifact defect the user has no way to notice.

The inline `os-pm` type is not affected: its package list lives in `werf.yaml` itself and feeds the stage digest through the generated command.

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Misconfiguration is surfaced, not silent (Priority: P1)

A user declares `packages: [{type: go-mod, workdir: /app}]` with a git mapping but forgets `stageDependencies.packages`. Today nothing tells them their dependency bumps will be ignored. After this change, every build emits a warning naming the image and the fix, and the warning is repeated in the end-of-run WARNINGS summary.

**Why this priority**: This is the only layer that reaches users with already-broken configurations; docs and fixtures only help those who read them.

**Independent Test**: Build a stapel image with a file-based packages directive, a git mapping, and no `stageDependencies.packages` — the warning appears. Add `stageDependencies.packages` — the warning disappears.

**Acceptance Scenarios**:

1. **Given** an image with a file-based packages directive and git mappings none of which declare `stageDependencies.packages`, **When** the user runs a build, **Then** a global warning names the image, explains that spec/lock changes will not rebuild the packages stage, and tells the user to declare `git.stageDependencies.packages`.
2. **Given** the same image with `stageDependencies.packages` declared on any git mapping, **When** the user runs a build, **Then** no such warning is emitted.
3. **Given** an image whose only packages directive is `os-pm`, **When** the user runs a build, **Then** no such warning is emitted.
4. **Given** an image with a file-based packages directive but no git mappings at all, **When** the user runs a build, **Then** no such warning is emitted (the files cannot come from git, so `stageDependencies` cannot help).

---

### User Story 2 - Correct configuration provably works (Priority: P2)

A user who declares `stageDependencies.packages: [go.mod, go.sum]` must get the promised behavior: bumping a dependency in `go.mod` rebuilds the packages stage and the SBOM reflects the new dependency; rebuilding without changes reuses the cached stage.

**Why this priority**: The warning tells users to adopt this pattern; the pattern itself must be covered by an automated end-to-end check, otherwise a regression would invalidate the advice.

**Independent Test**: The e2e suite drives a two-state go-mod fixture where only `go.mod` changes between states (werf.yaml identical) and asserts the packages stage rebuild directly via build output, not only via SBOM regeneration (which fires on any image change and would mask the regression).

**Acceptance Scenarios**:

1. **Given** a go-mod image with `stageDependencies.packages: [go.mod, go.sum]`, **When** it is built twice without changes, **Then** the second build reuses the cached packages stage and the cached SBOM.
2. **Given** the same image, **When** a new module is added to `go.mod` (werf.yaml unchanged), **Then** the packages stage is rebuilt and the regenerated SBOM contains the new module.

---

### User Story 3 - Shipped examples model the correct pattern (Priority: P3)

Fixtures and documentation are the templates users copy from. Every file-based e2e fixture declares `stageDependencies.packages`, and the stapel documentation (EN and RU) states the requirement with an example and explains why `os-pm` does not need it.

**Why this priority**: Prevents the trap from propagating through copy-paste and keeps e2e runs free of the new warning.

**Independent Test**: Grep the e2e fixtures: every werf.yaml with a file-based packages type also declares `stageDependencies.packages`; docs pages contain the pattern in both languages.

**Acceptance Scenarios**:

1. **Given** the e2e fixture set, **When** any fixture uses a file-based packages type, **Then** its git mapping declares `stageDependencies.packages` with the fixture's actual spec/lock files.
2. **Given** the stapel instructions documentation, **When** a reader reaches the file-based packages section, **Then** both the EN and RU versions document the `stageDependencies.packages` requirement with an example and note that `os-pm` is exempt.

### Edge Cases

- Multiple git mappings where only one declares `stageDependencies.packages`: no warning — any tracked mapping is sufficient.
- Mixed directives (`os-pm` + file-based) without `stageDependencies.packages`: warning fires — the file-based part is still unprotected.
- A `stageDependencies.packages` entry pointing to a file that does not exist (negative fixtures): the unmatched path contributes nothing to the checksum; builds behave as before.
- Multi-image projects: the warning is emitted per image (it names the image), unlike the once-per-run network warning, because the fix is per-image.

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: The build MUST emit a global warning for every stapel image that has at least one file-based packages directive (any type except `os-pm`), at least one git mapping, and no git mapping declaring a non-empty `stageDependencies.packages`.
- **FR-002**: The warning MUST name the image, state the consequence (spec/lock changes do not rebuild the packages stage; installed dependencies go stale while the SBOM reports the updated files), and name the fix (`git.stageDependencies.packages`).
- **FR-003**: The warning MUST be suppressed when the image has no git mappings, has no file-based packages directives, or any git mapping declares `stageDependencies.packages`.
- **FR-004**: Existing digest behavior MUST NOT change: no automatic injection of spec/lock paths into stage dependencies (no cache invalidation for existing users).
- **FR-005**: E2e coverage MUST assert the packages stage rebuild itself (via build output) when a tracked spec file changes with werf.yaml unchanged, and assert stage cache reuse on an unchanged rebuild.
- **FR-006**: All file-based e2e fixtures MUST declare `stageDependencies.packages` listing their actual spec/lock files, keeping e2e runs free of the new warning.
- **FR-007**: The stapel instructions documentation MUST describe the requirement identically in EN and RU, including an example and the `os-pm` exemption.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: A user with an untracked file-based packages directive sees the warning on every build, including in the end-of-run WARNINGS summary, and can resolve it by following the message alone (no docs lookup required).
- **SC-002**: With `stageDependencies.packages` declared, a spec-file-only change triggers a packages stage rebuild in 100% of builds, and an unchanged rebuild never triggers one.
- **SC-003**: Zero occurrences of the new warning across the whole e2e SBOM suite output.
- **SC-004**: Upgrading werf with this change causes zero stage cache invalidations for existing projects.

## Rejected Alternative

Automatically injecting spec/lock paths into the packages stage dependencies was rejected: `workdir` is a container path that cannot be reliably mapped back to git-repository paths (multiple git mappings, files produced by earlier stages or present in the base image), it would deviate from the explicit `stageDependencies` model shared by the install/beforeSetup/setup stages, and it would invalidate build caches for every existing user of file-based packages.

## Assumptions

- The trusted mechanism for file-change-driven stage invalidation is `git.stageDependencies` (shared with install/beforeSetup/setup stages); this feature documents and enforces awareness of it rather than replacing it.
- A warning (not a hard error) is the right severity: existing configurations keep building, matching the precedent of the stage-dependencies-without-instructions warning, with a potential future upgrade to an error.
- Users of file-based ecosystems keep their spec/lock files in git; files produced during the build or baked into the base image are out of scope for the warning (covered by the no-git-mappings suppression).
