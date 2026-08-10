# Implementation Plan: [FEATURE]

**Branch**: `[###-feature-name]` | **Date**: [DATE] | **Spec**: [link]

**Input**: Feature specification from `/specs/[###-feature-name]/spec.md`

**Note**: This template is filled in by the `/speckit-plan` command. See `.specify/templates/plan-template.md` for the execution workflow.

## Summary

[Extract from feature spec: primary requirement + technical approach from research]

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

[Gates determined based on constitution file]

**Environment note**: `task test:setup:environment` has already been executed
and the e2e/integration test environment is pre-configured. See the Environment
Configuration section in `.specify/memory/constitution.md`. Do not skip e2e tests
citing environment setup during implementation.

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

**Structure Decision**: Monolith CLI tool — `cmd/werf/` for command wiring, `pkg/...` for business logic. New feature code goes into the relevant `pkg/<domain>/` package and registers commands in `cmd/werf/<domain>/`.

## Complexity Tracking

> **Fill ONLY if Constitution Check has violations that must be justified**

| Violation | Why Needed | Simpler Alternative Rejected Because |
|-----------|------------|-------------------------------------|
| [e.g., 4th project] | [current need] | [why 3 projects insufficient] |
| [e.g., Repository pattern] | [specific problem] | [why direct DB access insufficient] |