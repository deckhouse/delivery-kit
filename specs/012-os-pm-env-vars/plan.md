# Implementation Plan: os-pm-env-vars

**Branch**: `012-os-pm-env-vars` | **Date**: 2026-07-30 | **Spec**: [spec.md](spec.md)

**Input**: Feature specification from `specs/012-os-pm-env-vars/spec.md`

## Summary

Add support for environment variables in the `packages[].env` field of `werf.yaml`. Users can set environment variables (e.g., `DOCKER_CONFIG`, `HTTP_PROXY`, `DEBIAN_FRONTEND`) that are passed to the package manager process (`pm install`) during container image builds. The `env` field is accepted in the config schema for all package types, but runtime behavior is only implemented for the `os-pm` type. Variable names are validated against POSIX naming rules at config parse time.

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

**Testing**: `testing` + `testify` (`assert`/`require`) for unit tests; Ginkgo for e2e tests

**Target Platform**: Linux (amd64/arm64) via Buildah; Kubernetes clusters

**Project Type**: CLI tool (Go binary via `cmd/werf/main.go`)

**Constraints**: CLI must be self-contained; no daemon dependency; POSIX filesystem operations; OCI-compatible registry interaction

**Performance Goals**: Container build throughput, image pull/push throughput, efficient stage caching

**Scale/Scope**: Single binary CLI tool with ~30+ subcommands across build, deploy, cleanup, SBOM, and auxiliary domains

**Key Code Paths**:

| File | Purpose |
|------|---------|
| `pkg/config/raw_packages_directive.go` | Raw YAML model for `packages[].env` — parse and validate |
| `pkg/config/packages_directive.go` | Validated `PackagesDirective` struct — add `Env` field, POSIX name validation |
| `pkg/config/packages_commands.go` | Shell command generation — inline env prefix before `pm install` |
| `pkg/config/raw_stapel_image.go` | Bridge — passes `PackagesDirective` to `GeneratePackagesCommands` |
| `pkg/build/builder/shell.go` | Shell builder — runs the generated commands in the container |
| `pkg/build/stage/packages.go` | Packages build stage — `NeedsNetwork = true` |

**Resolved**:
- `pm install` accepts env vars directly via inline prefix (`KEY=VALUE pm install ...`), exactly like the existing `PACKAGES_VERSION` and `REGISTRY` vars in `formatInstallCommand` (see `packages_commands.go:34-36`)
- Target solution: `ENV=value pm install ...` — inline env prefix, same as `envVarTmpl` pattern
- Existing tests: `packages_commands_test.go` has Ginkgo tests for `GeneratePackagesCommands` — they will need updating to add env var test cases

## Constitution Check

*GATE: Must pass before Phase 0 research. Re-check after Phase 1 design.*

| Gate | Status | Notes |
|------|--------|-------|
| **I. Simplicity Over Abstraction** | ✅ PASS | Adding a single `map[string]string` field to existing structs — no new abstractions, no interfaces, no generics. |
| **II. Go Idiomatic Code** | ✅ PASS | Standard Go maps, `fmt.Errorf` wrapping, `context.Context` where needed. |
| **III. Minimal Public Surface** | ✅ PASS | All changes internal to `pkg/config`. No new public API. |
| **IV. Test-Before-Merge** | ✅ PASS | Existing tests in `pkg/config/` will be updated; new tests for validation and command generation. |
| **V. Conventional Commits** | ✅ PASS | Feature branch follows commit conventions. |

**Result**: All gates pass. No complexity tracking needed.

## Project Structure

### Documentation (this feature)

```text
specs/012-os-pm-env-vars/
├── plan.md              # This file
├── research.md          # Phase 0 output
├── data-model.md        # Phase 1 output
├── quickstart.md        # Phase 1 output
├── contracts/           # Phase 1 output
└── tasks.md             # Phase 2 output (speckit-tasks command)
```

### Source Code (repository root)

```text
pkg/config/
├── raw_packages_directive.go   # + Env map[string]string field, YAML parsing
├── packages_directive.go       # + Env field on PackagesDirective, POSIX validation
├── packages_commands.go        # + env var export in command generation
└── raw_stapel_image.go         # No change (bridging is already generic)
```

## Complexity Tracking

*No constitution violations — all gates pass.*