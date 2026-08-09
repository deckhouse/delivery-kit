# Feature Specification: VEX Lifecycle in werf.yaml

**Feature Branch**: `013-vex-lifecycle`

**Created**: 2026-07-31

**Status**: Draft

**Input**: User description: "добавить vex в werf.yaml"

## Clarifications

### Session 2026-07-31

- Q: What functionality is explicitly out of scope for the initial VEX lifecycle implementation? → A: Custom VEX cleanup policies separate from SBOM — VEX uses SBOM cleanup rules for v1.
- Q: How should VEX OCI artifacts be named in the container registry to associate them with their source image? → A: OCI subject reference — VEX artifact attached to the image manifest (same pattern as SBOM).
- Q: What VEX file format and schema version should be supported? → A: OpenVEX (JSON-LD) — lightweight, simpler schema.
- Q: What observability signals should the VEX lifecycle produce for operators? → A: Build log messages only — VEX operations logged as part of the normal build output.
- Q: What performance constraints apply to VEX file size and the number of concurrent VEX artifacts per image? → A: No explicit constraints — VEX files are typically small (KB range); reuse SBOM pipeline limits.
- Q: How do image changes and VEX file changes interact during a build? → A: See Image-VEX Relationship Rules matrix — VEX is tied to image checksum, so image changes trigger VEX recreation even if VEX file is unchanged.

## Project Context

**Delivery Kit** is a Go CLI tool for full-cycle CI/CD to Kubernetes. It is built on top of werf with Deckhouse Platform extensions. Key subsystems:

- **Build** (`pkg/build/`) — Container image building via Buildah
- **Deploy** (`pkg/deploy/`) — Kubernetes deployment via werf/nelm (Helm-based)
- **SBOM** (`pkg/sbom/`) — Software Bill of Materials generation and validation
- **Cleanup** (`pkg/cleaning/`) — Container registry cleanup policies
- **Signature** (`pkg/signature/`) — Container image signing and verification
- **Docker Registry** (`pkg/docker_registry/`) — OCI registry operations
- **Config** (`pkg/config/`) — werf.yaml configuration parsing

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Configure VEX file for an image (Priority: P1)

A DevOps engineer wants to declare a VEX (Vulnerability Exploitability eXchange) document for a specific image in werf.yaml. During the image build and publish pipeline, the system reads the VEX file from the Git repository and saves it as an OCI artifact in the container registry alongside the image.

**Why this priority**: This is the core use case — without it, the feature delivers no value. All other stories depend on this.

**Independent Test**: Can be fully tested by adding a `vex` field to a single image in werf.yaml, running the build, and verifying the VEX document appears as an OCI artifact in the registry.

**Acceptance Scenarios**:

1. **Given** a werf.yaml with an image that has a `vex` field pointing to a valid VEX file under Git, **When** the build pipeline runs, **Then** the VEX document is published as an OCI artifact in the registry with the same repository and a reference to the image manifest.
2. **Given** a werf.yaml where an image has no `vex` field, **When** the build pipeline runs, **Then** the pipeline completes successfully without any VEX-related operations.
3. **Given** a werf.yaml with a `vex` field pointing to a non-existent file, **When** the build pipeline parses the configuration, **Then** an error is reported with a clear message about the missing file.
4. **Given** a werf.yaml with a `vex` field pointing to a file that exists but is not under Git tracking, **When** the build pipeline runs, **Then** an error is reported.

---

### User Story 2 - Update existing VEX document (Priority: P2)

A DevOps engineer modifies the VEX document in the Git repository and rebuilds the image. The system detects the change and publishes an updated VEX OCI artifact, replacing the previous version.

**Why this priority**: VEX documents evolve as new vulnerabilities are assessed. The ability to update is essential for maintaining accurate vulnerability status.

**Independent Test**: Can be tested by configuring a VEX file, building, then modifying the VEX file content, rebuilding, and verifying the registry contains the new version.

**Acceptance Scenarios**:

1. **Given** an image was previously built with a VEX document, **When** the VEX file content is changed and the image is rebuilt, **Then** the updated VEX document is published as a new version of the OCI artifact, preserving the same artifact repository name.
2. **Given** an image was previously built with a VEX document, **When** the image is rebuilt with no changes to either the image content or the VEX file, **Then** no new VEX artifact is published (the existing artifact is confirmed to match).
3. **Given** an image was previously built with a VEX document, **When** only the image content changes (but the VEX file remains unchanged), **Then** the VEX artifact is recreated because it is bound to the image checksum.

---

### User Story 3 - Cleanup VEX artifacts from registry (Priority: P2)

A DevOps engineer runs a registry cleanup policy. The system removes stale or unreferenced VEX OCI artifacts from the registry according to the same cleanup rules that apply to SBOM artifacts.

**Why this priority**: Without cleanup, VEX artifacts accumulate indefinitely and consume registry storage. Aligning with SBOM cleanup provides a consistent user experience.

**Independent Test**: Can be tested by creating multiple VEX artifact versions for an image, running cleanup, and verifying that only the retained versions remain in the registry.

**Acceptance Scenarios**:

1. **Given** a VEX artifact in the registry that is no longer referenced by any existing image tag or manifest, **When** cleanup runs with default policies, **Then** the orphaned VEX artifact is removed.
2. **Given** a VEX artifact in the registry that is referenced by a currently active image, **When** cleanup runs, **Then** the VEX artifact is retained.
3. **Given** a cleanup policy that explicitly excludes VEX artifacts, **When** cleanup runs, **Then** VEX artifacts are preserved regardless of their reference status.

---

### Edge Cases

- What happens when the VEX file specified in werf.yaml is empty or not a valid VEX format? The build should report a clear error.
- What happens when the registry does not support OCI artifacts for VEX storage? The build should fail with a descriptive error message.
- What happens when multiple images in the same werf.yaml reference the same VEX file? Each image gets its own VEX artifact attached via OCI subject reference.
- What happens when a VEX file is deleted from Git and the image is rebuilt? The build should fail.

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: werf.yaml MUST support an optional `vex` field within an image configuration block.
- **FR-002**: The `vex` field value MUST be a string containing the path to a VEX document file relative to the Git repository root.
- **FR-003**: The system MUST validate that the `vex` file path points to an existing file tracked by Git. If the file does not exist or is not tracked, the build MUST fail with a clear error message.
- **FR-004**: During the image build and publish pipeline, the system MUST save the VEX document as an OCI artifact in the same container registry where the image is stored.
- **FR-005**: The VEX OCI artifact MUST be stored as an OCI subject reference attached to the image manifest, using the same naming pattern as SBOM artifacts.
- **FR-006**: When the VEX file content changes between builds, the system MUST publish an updated VEX OCI artifact, creating a new version while retaining the same artifact repository.
- **FR-007**: The registry cleanup subsystem MUST handle VEX OCI artifacts with the same lifecycle rules as SBOM artifacts — unreferenced and expired VEX artifacts MUST be removed during cleanup. Custom VEX cleanup policies separate from SBOM are out of scope for v1.
- **FR-008**: The system MUST preserve VEX artifacts that are referenced by currently active image manifests during cleanup.
- **FR-009**: If the `vex` field is absent from all images in werf.yaml, the system MUST complete the build and publish pipeline without any VEX-related operations or errors.
- **FR-010**: When a `vex` field is present but the VEX file is empty or malformed, the system MUST report a validation error before starting the build.

#### Image-VEX Relationship Rules

The following matrix defines how changes to the image content and the VEX file interact during a build:

| Image changed | VEX changed | Result |
|--------------|-------------|--------|
| Yes | No | VEX is recreated because it is tied to the image checksum |
| No | Yes | New VEX artifact is created for the same image (same manifest, updated VEX) |
| Yes | Yes | Both the image manifest and the VEX artifact are updated |
| No | No | No VEX-related operations occur |

- **FR-011**: The VEX artifact MUST be bound to the image checksum — when the image content changes, the VEX artifact MUST be recreated even if the VEX file itself has not changed.

### Key Entities *(include if feature involves data)*

- **VEX Document**: A file in OpenVEX (JSON-LD) format containing vulnerability exploitability assessment information per the OpenVEX specification. Stored in the Git repository and published as an OCI artifact to the container registry.
- **VEX OCI Artifact**: The OCI representation of a VEX document stored in the container registry. It has its own manifest and is linked to the associated image manifest.
- **Image Configuration (`werf.yaml`)**: The configuration file where per-image settings are defined. The `vex` field is added as an optional property within an image block.
- **Cleanup Policy**: The set of rules governing which OCI artifacts (including VEX) are retained or removed from the registry during cleanup operations.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: Users can attach a VEX document to any image by adding a single optional `vex` field in werf.yaml, with zero configuration changes to their build pipeline.
- **SC-002**: VEX documents are stored as OCI artifacts in the registry and remain accessible for the same lifetime as the image they are associated with.
- **SC-003**: Updates to a VEX document are reflected in the registry within one build cycle, with no manual intervention required.
- **SC-004**: Registry cleanup removes orphaned VEX artifacts with the same retention and policy compliance as SBOM artifacts, preventing unbounded storage growth.
- **SC-005**: Existing werf.yaml configurations without `vex` fields continue to function identically after this feature is introduced (backward compatibility).

## Assumptions

- Users are familiar with the VEX specification and provide valid VEX documents.
- The container registry supports OCI artifact storage (as required by existing SBOM functionality).
- The VEX file format follows the OpenVEX (JSON-LD) schema.
- The build pipeline already has a mechanism for publishing SBOM artifacts; VEX publishing will follow the same pattern and share the same infrastructure.
- Cleanup rules for VEX artifacts mirror SBOM cleanup rules by default unless explicitly overridden by the user.
- The VEX file path in werf.yaml is relative to the Git repository root, consistent with other file path conventions already used in werf.yaml.

### Out of Scope (v1)

- Custom VEX cleanup policies separate from SBOM — VEX uses SBOM cleanup rules by default.