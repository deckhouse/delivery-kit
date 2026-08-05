# Implementation Plan: Hide OCI Attestation CLI Commands

**Branch**: `feat/hide-oci-attest-commands` | **Date**: 2026-07-20 | **Spec**: [spec.md](spec.md)

**Input**: Feature specification from `specs/008-hide-oci-attest-commands/spec.md`

## Summary

Hide the four `werf attest *` CLI commands (`sign`, `get`, `verify`, `ls`) and the parent `werf attest` command from help output and shell auto-completion by setting `Hidden: true` on each Cobra `Command` struct. No business logic, imports, or function signatures are altered — only a single-line boolean change per command.

## Technical Context

**Language/Version**: Go 1.24.10

**Primary Dependencies**:
- **CLI framework**: `github.com/spf13/cobra` — the `Hidden bool` field on `cobra.Command` is the sole mechanism used
- **Container building**: `containers/buildah` (werf fork: `werf/3p-buildah`), `containers/storage`, `containers/image`
- **Kubernetes deployment**: `werf/nelm`, `werf/kubedog`, Helm chart primitives
- **Kubernetes client**: `k8s.io/client-go`, `k8s.io/api`, `k8s.io/apimachinery`
- **Container registry**: `google/go-containerregistry`, `aws/aws-sdk-go-v2` (ECR)
- **SBOM**: `CycloneDX/cyclonedx-go`, `facebookincubator/nvdtools`
- **Utilities**: `samber/lo`, `werf/common-go`, `go-git/go-git`, `docker/docker` (API client)

**Storage**: OCI container registry (Docker v2, ECR), local git repository, Buildah container storage

**Testing**: `testing` + `testify` (`assert`/`require`) for unit tests; Ginkgo for e2e tests

**Target Platform**: Linux (amd64/arm64) via Buildah; Kubernetes clusters

**Project Type**: CLI tool (Go binary via `cmd/werf/main.go`)

**Performance Goals**: Container build throughput, image pull/push throughput, efficient stage caching

**Constraints**: CLI must be self-contained; no daemon dependency; POSIX filesystem operations; OCI-compatible registry interaction

**Scale/Scope**: Single binary CLI tool with ~30+ subcommands across build, deploy, cleanup, SBOM, and auxiliary domains

### Knowns

See [research.md](research.md) for the full analysis of the commands to hide, their locations, the `stageCmd` precedent, and technology choices.

### Unknowns (NEEDS CLARIFICATION)

None. The feature scope is fully clear: set `Hidden: true` on five Cobra commands.

## Constitution Check

*GATE: Must pass before Phase 0 research. Re-check after Phase 1 design.*

| Gate | Check | Status |
|------|-------|--------|
| Simplicity Over Abstraction | Adding `Hidden: true` fields is the simplest possible change — single booleans, no abstractions | ✅ PASS |
| Minimal Public Surface | Hiding commands from help output aligns with "keep minimal public surface" principle | ✅ PASS |
| Go Idiomatic Code | No new code style implications; existing pattern from `stageCmd` is reused | ✅ PASS |
| Test-Before-Merge | Existing tests must continue to pass unmodified | ✅ PASS |
| Conventional Commits | Change is a single logical commit | ✅ PASS |

**Verdict**: All gates pass. No complexity justification needed.

## Project Structure

### Documentation (this feature)

```text
specs/008-hide-oci-attest-commands/
├── plan.md              # This file
├── research.md          # Phase 0 output
├── data-model.md        # Phase 1 output
├── quickstart.md        # Phase 1 output
└── contracts/           # Phase 1 output
```

### Source Code (repository root)

```text
cmd/werf/
├── root/root.go              # attestCmd() — add Hidden: true to parent command
├── attest/
│   ├── sign/sign.go          # NewCmd() — add Hidden: true
│   ├── get/get.go            # NewCmd() — add Hidden: true
│   ├── verify/verify.go      # NewCmd() — add Hidden: true
│   └── ls/ls.go              # NewCmd() — add Hidden: true
└── ...
```

**Structure Decision**: Monolith CLI tool — `cmd/werf/` for command wiring, `pkg/...` for business logic. Changes are confined to `cmd/werf/` only, no `pkg/` changes.

## Complexity Tracking

Not needed — all constitution gates pass without violation.
