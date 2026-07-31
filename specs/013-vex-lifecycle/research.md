# Research: VEX Lifecycle in werf.yaml

**Date**: 2026-07-31
**Status**: Complete

## Overview

This document consolidates research findings for implementing VEX (Vulnerability Exploitability eXchange) document lifecycle support in werf.yaml. All NEEDS CLARIFICATION items from the plan's technical context have been resolved through codebase analysis.

## 1. SBOM Pattern Analysis

### Decision
VEX mirrors the existing SBOM implementation pattern end-to-end.

### Rationale
The feature spec (FR-005, FR-007) explicitly states VEX should use the same naming pattern as SBOM and the same cleanup rules. The SBOM implementation provides a well-tested, production-proven pattern for:
- Config parsing (raw YAML → normalized config)
- Giterminism validation (file tracking checks)
- OCI artifact creation (DSSE/in-toto envelope → subject reference)
- Artifact retrieval (digest → fallback index → pull → unwrap)
- Storage-level cleanup

### Alternatives Considered
- **Custom VEX OCI format without DSSE/in-toto**: Rejected because it would require separate retrieval/verification logic and inconsistent cleanup handling.
- **Storing VEX as a simple layer (no attestation envelope)**: Simpler but breaks consistency with SBOM and loses the in-toto statement subject binding that ties the VEX to a specific image digest.

### Key Files Analyzed

| File | Purpose |
|------|---------|
| `pkg/sbom/image/image.go` | SBOM publish/retrieve via DSSE/in-toto to OCI artifact store |
| `pkg/attestation/dsse.go` | DSSE envelope wrapping/unwrapping |
| `pkg/attestation/statement.go` | in-toto statement wrapping with subject digest |
| `pkg/attestation/predicate_types.go` | Well-known predicate types (includes `openvex`) |
| `pkg/attestation/sign.go` | Attestation signing (verification not needed for v1) |
| `pkg/oci/artifact/store.go` | OCIStore.Attach() — the core OCI artifact attachment |
| `pkg/oci/artifact/fallback.go` | Fallback index management for registries without subject-ref support |
| `pkg/config/raw_sbom.go` | Example of raw YAML → config parsing pattern |
| `pkg/config/sbom.go` | Normalized Sbom config type |
| `pkg/config/sbom_image.go` | Constructor: merges meta + image-level config |
| `pkg/build/sbom_step.go` | SBOM build step — pattern for VEX step |
| `pkg/build/build_phase.go` | Orchestration — `convergeSbomByImagesSets`, `convergeImageSbom` |
| `pkg/image/const.go` | OCI artifact annotations (`WerfImageNameAnnotation`, `WerfChecksumAnnotation`) |

## 2. VEX OCI Artifact Media Type

### Decision
Use `application/vnd.dsse.envelope.v1+json` as the artifact media type (same as SBOM) with an in-toto statement containing the VEX predicate. The VEX-specific differentiation comes from the predicate type URI (`https://openvex.dev/ns/v0.2.0`) inside the in-toto statement, not from a separate artifact media type.

### Rationale
- Consistency with SBOM — reuse the same DSSE media type, retrieval code, and fallback index logic.
- The artifact is distinguishable by predicate type when needed (e.g., for cleanup filtering).
- The `pkg/attestation` package already recognizes `openvex` as a well-known predicate type.

### Alternatives Considered
- **`application/vnd.werf.vex.v1+json`**: A custom media type would require separate OCI store lookups and separate cleanup filtering. More complex for zero benefit.
- **No envelope (raw JSON layer)**: Simpler but breaks the retrieval pattern and loses the subject binding to image digest.

## 3. Build Step Integration

### Decision
Create a separate `vexStep` that runs alongside `sbomStep` in the build pipeline.

### Rationale
- VEX has fundamentally different input — it reads a file from Git rather than generating a BOM from container image contents.
- SBOM step runs `containerBackend.GenerateSBOM()` (Syft scanner) — VEX doesn't need this.
- A separate step keeps the code clean and follows the Single Responsibility Principle.
- Both steps can run in parallel since they have no dependency on each other.

### Alternatives Considered
- **Extending `sbomStep`**: Would make the step responsible for two unrelated concerns. More complexity, harder to test.
- **Post-publish hook**: Would require a new extension mechanism not present in the build pipeline.

## 4. Config Model Design

### Decision
VEX is purely per-image — an optional `vex` field in each image block in werf.yaml. No meta-level toggle for v1.

### Rationale
- FR-009: If `vex` field is absent from all images, no VEX operations occur. A meta-toggle is redundant.
- FR-001, FR-002: Field is optional, path is relative to Git root.
- SBOM's `meta.build.sbom.enable` exists because SBOM generation can be expensive (Syft scanning). VEX just reads a file — negligible cost.
- Adding a meta-toggle later is backward-compatible.

### Config Shape (YAML)

```yaml
image: my-app
dockerfile: Dockerfile
vex: vex/my-app.openvex.json
```

## 5. OCI Artifact Attachment Flow

### Decision
Follow the exact SBOM publish pattern:
1. Read VEX JSON file from Git (validated by giterminism)
2. Wrap in in-toto statement with subject = image repo + digest hex, predicate type = `https://openvex.dev/ns/v0.2.0`
3. Wrap in DSSE envelope
4. Call `OCIStore.Attach(parentDigest, DSSEMediaType, envelope, checksum, targetPlatform)`

### Rationale
- Reuses the entire `pkg/oci/artifact` store with zero modifications.
- The DSSE envelope provides a consistent retrieval API (always unwrap DSSE → unwrap in-toto → read predicate).
- The checksum annotation enables caching — VEX is reprocessed only when the VEX file or image content changes.

### Key Constants

```go
const (
    VEXDSSEMediaType   = "application/vnd.dsse.envelope.v1+json"  // Same as SBOM
    VEXPredicateURI    = "https://openvex.dev/ns/v0.2.0"          // Already in WellKnownPredicateTypes
    InTotoMediaType    = "application/vnd.in-toto+json"           // Same as SBOM
)
```

## 6. Cleanup Integration

### Decision
VEX artifacts are cleaned up by the same cleanup code that handles SBOM artifacts. No separate cleanup logic.

### Rationale
- FR-007: "The registry cleanup subsystem MUST handle VEX OCI artifacts with the same lifecycle rules as SBOM artifacts."
- VEX and SBOM artifacts share the same OCI storage format (DSSE envelope attached via subject reference).
- The cleanup code already iterates over attached artifacts and can filter by predicate type if needed.
- For registries supporting OCI subject references, cleaning up the parent image manifest automatically makes the VEX artifact unreachable.
- For fallback-mode registries, the fallback index tracks all artifacts by image name. Cleanup removes entries that reference deleted images.

### Alternatives Considered
- **Dedicated VEX cleanup code**: Unnecessary — the existing artifact cleanup handles VEX artifacts correctly without changes.

## 7. CLI Command Structure

### Decision
Create `cmd/werf/vex/` with `get/` and `generate/` subcommands, following the same structure as `cmd/werf/sbom/`.

### Rationale
- Consistent user experience with the existing SBOM commands.
- `werf vex get` retrieves VEX from registry (mirrors `werf sbom get`).
- `werf vex generate` generates a VEX document template from image scan results (future — for v1, VEX files are authored manually).

### Commands (v1)

No new VEX CLI commands for v1. VEX documents are published and retrieved as part of the existing build and cleanup pipeline — no user-facing CLI needed.

## 8. OpenVEX Format

### Decision
Support OpenVEX JSON-LD format as specified by `https://openvex.dev/ns/v0.2.0`.

### Rationale
- Specified in clarification Q&A.
- Lightweight, simpler schema compared to alternatives.
- Already registered in `pkg/attestation.WellKnownPredicateTypes`.
- JSON-LD format means standard `encoding/json` works — no external dependency needed.

### Format Overview

OpenVEX documents contain:
- `@context`: `https://openvex.dev/ns/v0.2.0`
- `@id`: Document identifier (URI)
- `author`: Author of the VEX statement
- `role`: Document creator role
- `timestamp`: ISO 8601 timestamp
- `version`: Document version integer
- `statements`: Array of VEX statements, each containing:
  - `vulnerability`: Vulnerability identifier (e.g., CVE-2023-XXXXX)
  - `products`: Array of product identifiers (image references)
  - `status`: One of `not_affected`, `affected`, `fixed`, `under_investigation`
  - `justification`: (optional) Justification for the status
  - `impact_statement`: (optional) Human-readable impact statement
  - `action_statement`: (optional) Recommended action
  - `timestamp`: (optional) When this statement was issued