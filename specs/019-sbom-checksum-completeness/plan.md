# Implementation Plan: SBOM Checksum Completeness

**Branch**: `fix/sbom/checksum-completeness` | **Date**: 2026-08-24 | **Spec**: [spec.md](./spec.md)

**Input**: Feature specification from `/specs/019-sbom-checksum-completeness/spec.md`

## Summary

The SBOM artifact checksum (`sbomStep.calculateStableChecksum`, `pkg/build/sbom_step.go`) must encode every generation input outside the parent image content, so cached SBOM reuse is safe. Two gaps are fixed together in one PR (single invalidation wave):

1. Add the GOST configuration (`mergeOpts.Gost`) as an explicit, single-channel checksum part — NOT inside `MergeOpts.Checksum()` (FR-001, FR-002).
2. Replace `strings.Join(parts, "-")` + single hash with fixed-arity keyed parts passed to `util.Sha256Hash(parts...)`; no conditionally omitted parts (FR-003).

The os-pm packages directive and the scratch mode are covered by the parent digest and stay out of the checksum. The checksum contract and intentional exclusions (os-pm directive, scratch mode, gomod patcher inputs, externalref enrichment, generator logic → format version) get documented at the computation site (FR-006). See [research.md](./research.md) for the full input inventory and decisions.

## Technical Context

**Language/Version**: Go 1.24.10

**Primary Dependencies**:
- **Container building**: `containers/buildah` (werf fork: `werf/3p-buildah`), `containers/storage`, `containers/image`
- **Kubernetes deployment**: `werf/nelm`, `werf/kubedog`, Helm chart primitives
- **Kubernetes client**: `k8s.io/client-go`, `k8s.io/api`, `k8s.io/apimachinery`
- **Container registry**: `google/go-containerregistry`, `aws/aws-sdk-go-v2` (ECR)
- **SBOM**: `CycloneDX/cyclonedx-go`, `facebookincubator/nvdtools`
- **Utilities**: `samber/lo`, `werf/common-go`, `go-git/go-git`, `docker/docker` (API client)

**Storage**: OCI container registry (Docker v2, ECR), local git repository, Buildah container storage

**Testing**: Ginkgo + Gomega for all tests (unit and e2e)

**Target Platform**: Linux (amd64/arm64) via Buildah; Kubernetes clusters

**Project Type**: CLI tool (Go binary via `cmd/werf/main.go`)

**Performance Goals**: Container build throughput, image pull/push throughput, efficient stage caching

**Constraints**: CLI must be self-contained; no daemon dependency; POSIX filesystem operations; OCI-compatible registry interaction

**Scale/Scope**: Single binary CLI tool with ~30+ subcommands across build, deploy, cleanup, SBOM, and auxiliary domains

## Constitution Check

*GATE: Must pass before Phase 0 research. Re-check after Phase 1 design.*

- **I. Simplicity Over Abstraction**: PASS — pure-function change plus one small helper; no new interfaces, no new types.
- **II. Go Idiomatic Code**: PASS — no public API changes; helper stays unexported in `pkg/build`.
- **III. Minimal Public Surface**: PASS — nothing new exported; `MergeOpts.Checksum()` semantics untouched.
- **IV. Test-Before-Merge**: PASS — Ginkgo `DescribeTable` unit tests co-located in `pkg/build/sbom_step_test.go`; e2e in `test/e2e/sbom`.
- **V. Conventional Commits**: PASS — branch `fix/sbom/checksum-completeness`; commit `fix(sbom): ...` describing the user-visible symptom.

**Post-design re-check**: PASS — design adds one unexported helper (`gost config parts`) and modifies one function; no violations, Complexity Tracking empty.

**Lint**:
- **Prerequisites (once per session)**: run `task deps:install:golangci-lint`
  before the first lint run.
- **Usage**: then run the applicable lint task.

**Unit tests**:
- **Usage**: scoped example `task test:unit paths="./pkg/sbom/..."`.
- **Focused**: `task test:unit paths="./pkg/sbom/..." -- -focus=MyTest -v`.

**E2E tests**:
- **Prerequisites (once per session)**: the environment is already prepared. Do
  not run or check `task test:setup:environment` or skip tests for setup reasons.
- **Usage**: always run `task test:e2e` scoped with both `paths` and `labelFilter`.
  - Scoped: `task test:e2e paths="./test/e2e/sbom/..." labelFilter="sbom"`.
  - Focused: `task test:e2e paths="./test/e2e/sbom/..." labelFilter="sbom" -- -focus=MyTest -v`.

## Project Structure

### Documentation (this feature)

```text
specs/[###-feature]/
├── plan.md              # This file (/speckit-plan command output)
├── research.md          # Phase 0 output (/speckit-plan command)
├── data-model.md        # Phase 1 output (/speckit-plan command)
├── quickstart.md        # Phase 1 output (/speckit-plan command)
├── contracts/           # Phase 1 output (/speckit-plan command)
└── tasks.md             # Phase 2 output (/speckit-tasks command - NOT created by /speckit-plan)
```

### Source Code (repository root)

```text
cmd/werf/                    # CLI entry point and command tree (Cobra)
├── main.go
├── root/
├── build/
├── deploy/                  # converge, render, dismiss, rollback
├── helm/                    # Helm subcommands (install, upgrade, template, lint, secret)
├── cleanup/
├── export/
├── sbom/                    # get, merge, validate
├── config/                  # graph, list, render
├── common/                  # Shared CLI utilities and types
└── ...

pkg/                         # All business logic, organized by domain
├── build/                   # Image building pipeline
├── deploy/                  # Kubernetes deployment
├── sbom/                    # SBOM generation & validation
├── cleaning/                # Registry cleanup
├── docker_registry/         # Registry operations
├── config/                  # Configuration model
├── container_backend/       # Buildah/Docker abstraction
├── signature/               # Image signing
├── storage/                 # Abstract image storage
├── kubeutils/               # Kubernetes utilities
├── logging/                 # Structured logging
├── git_repo/                # Git operations
├── telemetry/               # Usage telemetry
└── ...

test/
├── e2e/                     # Ginkgo end-to-end tests
├── legacy_e2e/              # Legacy integration tests
└── pkg/                     # Shared test helpers
```

**Structure Decision**: Monolith CLI tool — `cmd/werf/` for command wiring, `pkg/...` for business logic. This feature touches only:

```text
pkg/build/sbom_step.go            # calculateStableChecksum: new parts, keyed encoding, contract doc
pkg/build/sbom_step_test.go       # DescribeTable: each input flips checksum; stability
test/e2e/sbom/                    # GOST-toggle regeneration scenario + fixtures
```

`pkg/sbom/cyclonedxutil/merge.go` (`MergeOpts.Checksum`) and `pkg/sbom/cyclonedxutil/gost/config.go` are read but NOT modified (FR-004 keeps GOST out of MergeOpts.Checksum).

## Implementation Outline

1. **`calculateStableChecksum`** (pkg/build/sbom_step.go):
   - Signature unchanged; gost config already reachable via `mergeOpts.Gost`.
   - Parts become fixed-arity keyed arguments to `util.Sha256Hash(parts...)`:
     `formatVersion; "scan", scanOpts.Checksum(); "merge", mergeOpts.Checksum(); "gost_attack_surface", v; "gost_security_function", v; "signer", signerIdentity; "platform", targetPlatform` — every part always present, empty string when unset.
   - Doc comment states the contract: checksum covers all generation inputs outside the parent image digest; lists intentional exclusions (FR-007).
2. **Tests**: unit table per R6; e2e toggle scenario per quickstart.md.
3. **No `sbomArtifactFormatVersion` bump** — layout change already invalidates once (R4).

## Risks

- **One-time regeneration wave** for all users on upgrade — accepted (spec Edge Cases, FR-007); all changes land in one PR.
- **Checksum stability regression** (accidental non-determinism) — guarded by the stability unit test (SC-004).

## Complexity Tracking

> **Fill ONLY if Constitution Check has violations that must be justified**

| Violation | Why Needed | Simpler Alternative Rejected Because |
|-----------|------------|-------------------------------------|
| [e.g., 4th project] | [current need] | [why 3 projects insufficient] |
| [e.g., Repository pattern] | [specific problem] | [why direct DB access insufficient] |