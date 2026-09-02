# Feature Specification: VEX Convergence Without Configuration

**Feature Branch**: `fix/vex/skip-converge-without-config`

**Created**: 2026-09-02

**Status**: migrated

**Input**: Reverse-engineered from commit `b30d77ac1` (`refactor(vex): check VEX configuration before resolving stage descriptor`)

## Project Context

Delivery Kit is a Go CLI tool for full-cycle CI/CD to Kubernetes. This change belongs to the image build pipeline in `pkg/build/`, specifically VEX artifact convergence after image publication.

## Background

VEX convergence runs for each image when stages are stored in a registry. Previously, `convergeImageVex` attempted to resolve a stage descriptor before checking whether the image configured VEX. An image without VEX could therefore perform unnecessary descriptor resolution and fail with `stage descriptor is unavailable`, despite requiring no VEX operation.

## User Scenarios & Testing

### User Story 1 - Ignore images without VEX configuration (Priority: P1)

As a build user, I want images without VEX configuration to pass through VEX convergence without registry or descriptor work, so existing builds remain unaffected.

**Why this priority**: This is the regression fix and preserves backward-compatible behavior for the common case where VEX is not used.

**Independent Test**: Invoke VEX convergence for single-platform and multiplatform images without VEX and without stage descriptors; both calls complete successfully.

**Acceptance Scenarios**:

1. **Given** a single-platform image without VEX and without a stage descriptor, **when** VEX convergence runs, **then** it succeeds without resolving a descriptor.
2. **Given** a multiplatform image without VEX and without a registered stage descriptor, **when** VEX convergence runs, **then** it succeeds without resolving a descriptor.
3. **Given** an image with an empty VEX document configuration, **when** VEX convergence runs, **then** it succeeds without VEX operations.

### User Story 2 - Converge configured VEX only with a valid descriptor (Priority: P1)

As a build user, I want configured VEX to fail clearly when its image descriptor is unavailable, while retaining descriptor lookup for valid images.

**Independent Test**: Exercise descriptor lookup for reused single-platform images, registered multiplatform images, and missing descriptors; verify the selected descriptor or expected error.

**Acceptance Scenarios**:

1. **Given** VEX is configured and a single-platform image has a last non-empty stage descriptor, **when** convergence runs, **then** that descriptor is used.
2. **Given** VEX is configured and a registered multiplatform image has a stage descriptor, **when** convergence runs, **then** the registered multiplatform descriptor is used.
3. **Given** VEX is configured but no applicable descriptor exists, **when** convergence runs, **then** it returns `unable to converge VEX for image "<name>": stage descriptor is unavailable`.

## Edge Cases

- An empty image list is a no-op.
- A multiplatform image that was never registered has no implicit descriptor fallback.
- A missing descriptor is an error only after VEX configuration has been confirmed.

## Requirements

### Functional Requirements

- **FR-001**: VEX convergence MUST return successfully without descriptor resolution when the image list is empty.
- **FR-002**: VEX convergence MUST inspect the primary image's VEX configuration before resolving a stage descriptor.
- **FR-003**: A nil VEX configuration MUST result in a no-op.
- **FR-004**: A VEX configuration with an empty document MUST result in a no-op.
- **FR-005**: For a single-platform image, descriptor lookup MUST use `GetLastNonEmptyStageDesc`.
- **FR-006**: For a multiplatform image, descriptor lookup MUST use the registered image tree entry's `GetStageDesc`.
- **FR-007**: VEX convergence MUST NOT synthesize an unregistered multiplatform image merely to obtain a descriptor.
- **FR-008**: When VEX is configured and the descriptor is unavailable, convergence MUST return a clear image-specific error.
- **FR-009**: Existing VEX file reading and publishing behavior MUST remain unchanged after descriptor resolution succeeds.

## Success Criteria

- **SC-001**: Images without VEX configuration complete VEX convergence successfully even when no stage descriptor exists.
- **SC-002**: Empty VEX documents produce no VEX-related error or operation.
- **SC-003**: Configured VEX with a missing descriptor consistently produces the documented image-specific error.
- **SC-004**: Single-platform and registered multiplatform descriptor lookup paths are covered by co-located Ginkgo/Gomega tests.
- **SC-005**: Existing builds that do not configure VEX retain their previous successful behavior.

## Assumptions and Scope

- The broader VEX lifecycle (configuration parsing, artifact publishing, signing, and cleanup) is covered by existing VEX specifications and is out of scope here.
- This change does not add CLI flags, configuration fields, external dependencies, or e2e scenarios.
- The specification describes behavior already implemented on the migration branch; it is not a proposal for new code.
