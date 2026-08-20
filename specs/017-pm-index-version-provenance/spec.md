# Feature Specification: PM Index Version Provenance in os-pm SBOM

**Feature Branch**: `feat/sbom/pm-index-version-property`

**Created**: 2026-08-19

**Status**: Implemented (retroactive specification)

**Input**: User description: "Ensure the SBOM for pm records the pm index version: write the version into the purl of every os-pm component and into component properties; the os-pm SBOM section must not be influenced by the PM_LOCK_FILE environment variable." (Kaiten card 68684730, part of epic "SBOM для РБПО. Managed inputs")

## Project Context

**Delivery Kit** is a Go CLI tool for full-cycle CI/CD to Kubernetes. It is built on top of werf with Deckhouse Platform extensions. Key subsystems:

- **Build** (`pkg/build/`) — Container image building via Buildah
- **Deploy** (`pkg/deploy/`) — Kubernetes deployment via werf/nelm (Helm-based)
- **SBOM** (`pkg/sbom/`) — Software Bill of Materials generation and validation
- **Cleanup** (`pkg/cleaning/`) — Container registry cleanup policies
- **Signature** (`pkg/signature/`) — Container image signing and verification
- **Docker Registry** (`pkg/docker_registry/`) — OCI registry operations
- **Config** (`pkg/config/`) — werf.yaml configuration parsing

Packages installed via the pm package manager (the `packages` directive, ecosystem `os-pm`) are delivered from a versioned package index published by the container factory. The version of that index (the container factory version) identifies exactly which package set a build consumed. SBOM consumers performing secure software development lifecycle (РБПО) audits must be able to trace every pm-installed component back to the index release it came from.

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Auditor traces a pm component to its index release (Priority: P1)

A security auditor inspects the SBOM of a built image and, for every component installed via pm, immediately sees which version of the pm package index the component was taken from — both in the component's package URL and in its properties, so that any SBOM tooling (purl-based or property-based) can extract it.

**Why this priority**: This is the core РБПО traceability requirement — without the index version recorded in the SBOM, a component version alone does not identify the exact supply-chain input.

**Independent Test**: Build an image with a `packages` directive, extract its SBOM, and inspect any os-pm component: the index version must appear as a purl qualifier and as a component property.

**Acceptance Scenarios**:

1. **Given** an image built with pm-installed packages and a known index version, **When** the SBOM is generated, **Then** every os-pm component's purl contains a `containerfactoryversion` qualifier equal to that index version.
2. **Given** the same build, **When** the SBOM is generated, **Then** every os-pm component carries a `werf:pm:containerFactoryVersion` property equal to that index version.
3. **Given** the same build, **When** the SBOM dependency graph is generated, **Then** dependency references between os-pm components use the same qualified purls, keeping the graph internally consistent.

---

### User Story 2 - Index version cannot be spoofed via environment (Priority: P1)

A build engineer must be certain that nothing inside the image environment (in particular the `PM_LOCK_FILE` environment variable, which can redirect pm to a different index file at runtime) can change which package data or index version ends up in the SBOM.

**Why this priority**: If the SBOM data source could be redirected by an environment variable baked into a base image, the provenance record would be untrustworthy — defeating the purpose of recording it.

**Independent Test**: Grep the codebase for `PM_LOCK_FILE` and audit the os-pm SBOM data sources: package data must come only from `pm.lock` in the git build context, and the index version only from a fixed, non-overridable path inside the built image.

**Acceptance Scenarios**:

1. **Given** the os-pm SBOM generation code, **When** its data sources are audited, **Then** the `PM_LOCK_FILE` environment variable is not consulted anywhere.
2. **Given** a build, **When** the SBOM is generated, **Then** package names, versions, licenses and dependencies come exclusively from `pm.lock` committed in the build context, and the runtime index file inside the image is never read.
3. **Given** a build, **When** the index version is collected, **Then** it is read from the fixed path `/var/lib/pm/container-factory-version` inside the built image, written there during package installation from the mandatory `PACKAGES_VERSION` build secret.

---

### User Story 3 - SBOM survives a base image without a version file (Priority: P2)

A user builds on top of a base image whose pm installation predates the version file. SBOM generation still succeeds: components are emitted without the version qualifier and without the version property, rather than failing the build or recording a fabricated value.

**Why this priority**: Backward compatibility — failing every build on legacy base images would block adoption, and recording an empty or invented version would corrupt provenance data.

**Independent Test**: Generate an SBOM with an empty index version and verify components carry no `containerfactoryversion` qualifier value and no `werf:pm:containerFactoryVersion` property.

**Acceptance Scenarios**:

1. **Given** an image where `/var/lib/pm/container-factory-version` does not exist, **When** the SBOM is generated, **Then** generation succeeds and os-pm components are present.
2. **Given** an unknown (empty) index version, **When** component properties are emitted, **Then** the `werf:pm:containerFactoryVersion` property is omitted entirely rather than emitted with an empty value.

---

### Edge Cases

- Empty or missing `pm.lock` in the build context: the os-pm SBOM section is skipped entirely (no components fabricated); if `pm.yaml` exists without `pm.lock`, the build fails with an instruction to run `pm lock`.
- New installs cannot silently lose provenance: package installation requires the `PACKAGES_VERSION` secret and fails without it, so only pre-existing base-image layers can lack the version file.
- Components with no declared dependencies produce no dependency-graph entries (no empty references).

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: Every SBOM component describing a pm-installed package MUST include the pm index version (container factory version) as the `containerfactoryversion` qualifier of its package URL.
- **FR-002**: Every SBOM component describing a pm-installed package MUST include the pm index version as the component property `werf:pm:containerFactoryVersion`.
- **FR-003**: Dependency references between os-pm components in the SBOM dependency graph MUST use the same qualified package URLs as the components themselves.
- **FR-004**: The os-pm SBOM section MUST NOT consult the `PM_LOCK_FILE` environment variable or any other runtime-overridable path configuration.
- **FR-005**: Package identity data (names, versions, licenses, digests, dependencies) for the os-pm SBOM section MUST come exclusively from `pm.lock` committed in the git build context; the runtime package index inside the image MUST NOT be read.
- **FR-006**: The index version MUST be read from the fixed path `/var/lib/pm/container-factory-version` inside the built image, populated at package installation time from the mandatory `PACKAGES_VERSION` build secret.
- **FR-007**: When the index version is unavailable in the built image, SBOM generation MUST succeed, and the `werf:pm:containerFactoryVersion` property MUST be omitted (never emitted empty).

### Key Entities

- **PM package index (container factory release)**: The versioned package set published by the container factory; its version is the provenance value this feature records.
- **pm.lock**: Deterministic lock file in the git build context; sole source of os-pm package identity data for the SBOM.
- **Container factory version file**: `/var/lib/pm/container-factory-version` inside the image; carries the index version from install time to SBOM generation time.
- **os-pm SBOM component**: CycloneDX component of a pm-installed package; carries the index version in its purl qualifier and its properties.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: 100% of os-pm components in a generated SBOM carry the index version in both their package URL and their properties when the version is available in the image.
- **SC-002**: An auditor can determine the index version of any pm-installed component from the SBOM alone, without access to the build environment.
- **SC-003**: A codebase audit finds zero code paths where an environment variable influences which files feed the os-pm SBOM section.
- **SC-004**: Builds on base images lacking the version file continue to produce valid SBOMs with zero generation failures attributable to the missing version.

## Assumptions

- The container factory version and the pm index version are the same value: the factory publishes the index, and `PACKAGES_VERSION` identifies that release.
- The purl qualifier name `containerfactoryversion` and property name `werf:pm:containerFactoryVersion` are the agreed public contract for this provenance value; downstream tooling matches on these names.
- Determinism of the package data source (pm.lock in git, runtime index not read) is established by spec `015-enforce-pm-determinism-again`; this feature builds on it and only adds the provenance value.
- Verification at the unit level (component conversion) is sufficient; end-to-end SBOM tests covering the packages directive already exist and exercise the same code path.
