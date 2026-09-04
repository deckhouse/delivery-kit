# Feature Specification: SBOM Without Syft Scan for Stapel Images Without Packages

**Feature Branch**: `fix/build/skip-syft-without-packages`

**Created**: 2026-09-04

**Status**: implemented

**Input**: Derived from commit `2a7c283c9` (`fix(sbom): stop syft scans for stapel images without packages`)

## Project Context

Delivery Kit is a Go CLI tool for full-cycle CI/CD to Kubernetes. This change belongs to the SBOM convergence step of the image build pipeline in `pkg/build/`, which decides how each built image obtains its SBOM artifact.

## Background

SBOM convergence runs for every image when `build.sbom.enable` is set. Previously, a stapel image whose config declared no `packages` directive — for example an image defined only by `image`, `from` and werf-managed instructions — was scanned by syft in full. Such an image carries no user-managed package content of its own: everything in it comes from the base image, imports and werf-managed instructions. The full scan produced a redundant SBOM (duplicating the base image contents at scan quality rather than attested quality) and cost a syft container run per image. The only cases that skipped the scan were os-pm-only images and scratch-based images.

## User Scenarios & Testing

### User Story 1 - Derive the SBOM of a package-less stapel image from its base (Priority: P1)

As a build user, I declare an image as a thin layer over a digest-pinned base image:

```yaml
image: builder/golang
from: registry.example.io/factory@sha256:...
final: false
```

I want its SBOM to be the attested SBOM of the base image, without a syft scan of the derived image.

**Why this priority**: This is the behavior change: it removes redundant scanning and makes the derived image's SBOM authoritative — the base image's attached SBOM merged with import SBOMs — instead of a re-scan.

**Independent Test**: Build a stapel image without a `packages` directive with SBOM enabled; the build produces an attached SBOM artifact without running syft against the image.

**Acceptance Scenarios**:

1. **Given** a stapel image without a `packages` directive, **when** SBOM convergence runs, **then** syft does not scan the image and the resulting SBOM is the merge of the base image SBOM and import SBOMs.
2. **Given** a stapel image without a `packages` directive whose base image has an attached SBOM, **when** SBOM convergence runs, **then** the base image's SBOM components appear in the resulting SBOM.
3. **Given** a stapel image without a `packages` directive whose base is a trusted builder image without an attached SBOM, **when** SBOM convergence runs, **then** the resulting SBOM is produced without error and contains no base components (existing `ErrSbomNotRequired` semantics).

### User Story 2 - Keep targeted scanning for declared packages (Priority: P1)

As a build user, I want images that declare `packages` to keep their existing SBOM quality: file-based ecosystems are cataloged by syft, and os-pm packages are collected from the runtime index.

**Independent Test**: Build one image with a file-based `packages` directive and one with an os-pm-only directive; the first is scanned by syft with targeted catalogers, the second collects the runtime package index without a syft scan.

**Acceptance Scenarios**:

1. **Given** a stapel image with a file-based `packages` directive (e.g. pip, npm), **when** SBOM convergence runs, **then** syft scans the image with the catalogers derived from the directive and the result is filtered to the declared source paths.
2. **Given** a stapel image with only an os-pm `packages` directive, **when** SBOM convergence runs, **then** syft does not scan the image and the os-pm runtime index is merged into the SBOM (unchanged behavior).
3. **Given** a Dockerfile-based image, **when** SBOM convergence runs, **then** syft scans the image in full (unchanged behavior).

## Edge Cases

- A scratch-based stapel image without `packages` keeps its previous behavior (no scan, empty target BOM); the previous scratch-specific condition is subsumed by the new rule.
- A stapel image with `shell`/`git` instructions but without `packages` is not scanned: content added by such instructions is not user-managed package input and is out of SBOM scope by design.
- An image whose base has no attached SBOM and is not a trusted builder image fails SBOM convergence with the existing "must have an SBOM artifact attached" error (unchanged behavior, now the primary source of the derived image's components).

## Requirements

### Functional Requirements

- **FR-001**: SBOM convergence MUST NOT run a syft scan for a stapel image whose scan options carry no catalogers (no file-based `packages` directives).
- **FR-002**: For such images the resulting SBOM MUST be the merge of the base image SBOM, import image SBOMs and, when declared, the os-pm runtime index.
- **FR-003**: The target BOM metadata for a skipped scan MUST still identify the image (repository and tag), as before.
- **FR-004**: A stapel image with file-based `packages` directives MUST keep the targeted cataloger scan and source-path filtering.
- **FR-005**: A Dockerfile-based image MUST keep the full syft scan.
- **FR-006**: The SBOM artifact format version MUST be bumped so SBOM artifacts generated by the previous logic are regenerated instead of reused from the registry cache.
- **FR-007**: BOM patchers (gomod, PM, external references) and GOST property handling MUST apply to the merged result exactly as they applied to scanned results.

## Success Criteria

- **SC-001**: A build of a stapel image without `packages` produces an attached SBOM artifact without pulling or running the syft scanner image for it.
- **SC-002**: The SBOM of such an image reflects its base image's attested SBOM rather than an independent scan.
- **SC-003**: Images with file-based `packages`, os-pm-only images and Dockerfile images produce byte-equivalent SBOM decisions to the previous release (scan targeted / collect index / scan full).
- **SC-004**: Rebuilding an unchanged image after upgrading regenerates its SBOM once (format version bump) and then reuses the registry cache.
- **SC-005**: The scan/skip decision is covered by a co-located Ginkgo table test whose entries fail under inversion of either decision input.

## Assumptions and Scope

- The base image SBOM requirement (attached artifact or trusted builder exemption) is pre-existing behavior and is not changed here.
- No CLI flags, configuration fields or external dependencies are added.
- The specification describes behavior already implemented on the feature branch; it is not a proposal for new code.
