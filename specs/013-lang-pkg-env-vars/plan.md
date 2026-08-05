# Implementation Plan: lang-pkg-env-vars

**Branch**: `013-lang-pkg-env-vars` | **Date**: 2026-08-03 | **Spec**: [spec.md](spec.md)

**Input**: Feature specification from `specs/013-lang-pkg-env-vars/spec.md`

## Summary

Enable runtime environment variable support for all language package manager types (`go-mod`, `python-uv`, `python-pip`, `python-poetry`, `rust-cargo`, `javascript-npm`, `javascript-yarn`, `javascript-pnpm`, `lua-rock`) by wiring the `packages[].env` field — already parsed and validated by the config layer — into the `InstallCmd` functions that generate shell commands for each ecosystem. The mechanism (inline shell prefix via `formatEnvVars()`) already exists from the `os-pm` feature; this plan extends it to 9 language types with zero config schema changes.

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

**Performance Goals**: Container build throughput, image pull/push throughput, efficient stage caching

**Constraints**: CLI must be self-contained; no daemon dependency; POSIX filesystem operations; OCI-compatible registry interaction

**Scale/Scope**: Single binary CLI tool with ~30+ subcommands across build, deploy, cleanup, SBOM, and auxiliary domains

**Key Technical Details**:

- **Configuration model**: `PackagesDirective` struct in `pkg/config/packages_directive.go` already has an `Env map[string]string` field that is parsed from YAML and POSIX-validated at config parse time (`raw_packages_directive.go`).
- **Command generation**: `GeneratePackagesCommands()` in `pkg/config/packages_commands.go` calls each ecosystem's `InstallCmd` function with the `pkg.Env` map already passed as the 4th argument.
- **Current state**: All 9 language types (`GoMod`, `PythonUV`, `PythonPip`, `PythonPoetry`, `RustCargo`, `JavaScriptNpm`, `JavaScriptYarn`, `JavaScriptPnpm`, `LuaRock`) have `InstallCmd` implementations that accept `env map[string]string` but bind it to `_` — they ignore it.
- **OS PM pattern**: `PackagesDirectiveTypeOSPM` is the only type that uses `env` — it calls `formatEnvVars(env)` to produce an inline shell prefix (e.g., `KEY="val" pm install curl`).
- **Available helper**: `formatEnvVars(map[string]string) string` in `packages_commands.go` is a package-private function that sorts env keys alphabetically and returns an inline shell prefix string.
- **Build execution**: Generated commands flow through `Shell.Packages []string` → `stage` builder → container script execution. The SBOM gate at `raw_stapel_image.go:329` controls whether `GeneratePackagesCommands()` is called at all.
- **No config schema changes needed**: The `env` field is already parsed, validated, and stored for all package types. This feature is purely a runtime wiring change.

## Constitution Check

*GATE: Must pass before Phase 0 research. Re-check after Phase 1 design.*

| Gate | Status | Justification |
|------|--------|---------------|
| **I. Simplicity > Abstraction** | ✅ PASS | Directly wiring env into 9 `InstallCmd` funcs — simplest possible change; no new interfaces, types, or abstractions |
| **II. Go Idiomatic Code** | ✅ PASS | Uses existing `formatEnvVars` helper; no new public API surface beyond what `PackagesDirective` already defines |
| **III. Minimal Public Surface** | ✅ PASS | All changes are internal to `pkg/config`; no new exported symbols |
| **IV. Test-Before-Merge** | ✅ PASS | Tests co-located with source; existing Ginkgo DescribeTable patterns to extend |
| **V. Conventional Commits** | ✅ PASS | Single commit: `feat(config): wire env vars into language package manager install commands` |
| **Code Boundaries** | ✅ PASS | Changes confined to `pkg/config/packages_directive.go` (InstallCmd funcs) and `pkg/config/packages_commands_test.go` (tests) |
| **Dependency Rules** | ✅ PASS | No new dependencies introduced |
| **Build & Quality Gates** | ✅ PASS | `task build`, `task format`, `task lint`, `task test:unit` all applicable |

**No violations or justified exceptions needed.**

## Project Structure

### Documentation (this feature)

```text
specs/013-lang-pkg-env-vars/
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
├── config/                  # Configuration model — THIS IS WHERE CHANGES GO
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

No violations recorded. This feature is a simple wiring change with no complexity trade-offs.

| Violation | Why Needed | Simpler Alternative Rejected Because |
|-----------|------------|-------------------------------------|
| — | — | — |