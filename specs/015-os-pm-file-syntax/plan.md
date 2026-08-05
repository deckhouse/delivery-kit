# Implementation Plan: os-pm File-Based Syntax

**Branch**: `015-os-pm-file-syntax` | **Date**: 2026-08-05 | **Spec**: [spec.md](spec.md)

**Input**: Feature specification from `/specs/015-os-pm-file-syntax/spec.md`

**Note**: This template is filled in by the `/speckit-plan` command. See `.specify/templates/plan-template.md` for the execution workflow.

## Summary

The `os-pm` package type in werf currently uses an inline syntax where OS packages are declared as a list of strings in `werf.yaml` (e.g., `spec: [curl==8.12.1, jq]`). This feature replaces the inline syntax with a file-based syntax using `pm.yaml` (spec file) and `pm.lock` (lock file) at the repository root — consistent with how Go, Rust, Python, JavaScript, and other package types are handled. Key changes: register `os-pm` in the ecosystems registry with `DefaultSpecFile: "pm.yaml"` and `DefaultLockFile: "pm.lock"`; use `pm sync --from <lockfile>` as the install command; remove the special-cased `os-pm` branches in `fillFileBasedSpec()` and `validate()`; remove the now-unused `PackagesSpec` struct; reject `workdir` for `os-pm`; wire up SBOM cataloging for `pm.yaml`/`pm.lock` via the `CatalogerName` field.

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

### Code Locations

Key files that need changes:

- **`pkg/config/packages_directive.go`** — `PackagesSpec` struct removal, `PackagesDirective` struct simplification, `ecosystems` map registration for `os-pm` (add `DefaultSpecFile`, `DefaultLockFile`, `CatalogerName`, new `InstallCmd`), `validate()` method de-specialize `os-pm`, `Ecosystems()` used by SBOM
- **`pkg/config/raw_packages_directive.go`** — `fillFileBasedSpec()` de-specialize `os-pm` branch; `spec` field validation as string (not list of strings) for `os-pm`; `workdir` rejection
- **`pkg/config/packages_commands.go`** — `GeneratePackagesCommands()` needs no changes (already uses `eco.InstallCmd`), but the `formatInstallCommand()` function for the old inline `pm install` syntax may be removable or kept for reference
- **`pkg/sbom/managedinput/managedinput.go`** — `buildResolvers()` skips ecosystems with empty `CatalogerName`; once `os-pm` has a `CatalogerName`, it automatically gets a cataloger with source paths `pm.yaml` and `pm.lock` at the repository root
- **`pkg/build/builder/`** — Builder interface may need `HasOSPMPackages()` → `OSPMLockPath()` change if the build phase uses lock path instead of boolean flag (NEEDS CLARIFICATION)
- **Test files** — `packages_directive_*_test.go`, `raw_packages_directive_test.go`, `packages_commands_test.go`, `managedinput_test.go` all reference the old inline `os-pm` syntax and need updating

### Unknowns

1. **Builder interface change** — The spec mentions `HasOSPMPackages()` → `OSPMLockPath()` (FR-011). Need to trace how the builder currently detects `os-pm` packages and passes info to the build stage. Explore `pkg/build/builder/shell.go` and how `GeneratePackagesCommands()` is called.
2. **Test fixture locations** — Test YAML fixtures or test data may reference the inline `os-pm` syntax and need updating.
3. **Git stage dependencies behavior** — Already supported for all package types per FR-013, but verify there's no `os-pm` specific exclusion.
4. **Build phase command wiring** — Trace how the build phase generates and runs `pm sync` commands from `GeneratePackagesCommands()`.

## Constitution Check

*GATE: Must pass before Phase 0 research. Re-check after Phase 1 design.*

| Principle | Check | Status |
|-----------|-------|--------|
| **I. Simplicity Over Abstraction** | Removing a special-cased inline syntax in favor of the standard `FileBasedSpec` path reduces complexity — one less code branch, one less struct (`PackagesSpec`), consistent with all other package types. | ✅ PASS |
| **II. Go Idiomatic Code** | No changes to public API signatures beyond the optional `HasOSPMPackages()` → `OSPMLockPath()` rename. | ✅ PASS |
| **III. Minimal Public Surface** | The change shrinks the public surface by removing `PackagesSpec` and the special-cased `os-pm` validation/parsing branches. | ✅ PASS |
| **IV. Test-Before-Merge** | All test fixtures and assertions using inline `os-pm` syntax must be updated. This is a substantial but mechanical change. | ⚠️ PASS with conditions |
| **V. Conventional Commits** | Standard commit format applies. No unusual patterns. | ✅ PASS |

**GATE**: No violations — proceed to Phase 0.

## Project Structure

### Documentation (this feature)

```text
specs/015-os-pm-file-syntax/
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
│   ├── packages_directive.go        # Ecosystems registry, types, validation
│   ├── raw_packages_directive.go    # YAML unmarshal, fillFileBasedSpec
│   ├── packages_commands.go         # Command generation
│   └── ...test.go                   # Test files with inline os-pm syntax
├── container_backend/       # Buildah/Docker abstraction
├── signature/               # Image signing
├── storage/                 # Abstract image storage
├── kubeutils/               # Kubernetes utilities
├── logging/                 # Structured logging
├── git_repo/                # Git operations
├── telemetry/               # Usage telemetry
└── ...


test/
├── e2
e/                     # Ginkgo end-to-end tests
├── legacy_e2e/              # Legacy integration tests
└── pkg/                     # Shared test helpers
```

**Structure Decision**: Monolith CLI tool — `cmd/werf/` for command wiring, `pkg/...` for business logic. New feature code goes into the relevant `pkg/<domain>/` package and registers commands in `cmd/werf/<domain>/`.

## Complexity Tracking

> **Fill ONLY if Constitution Check has violations that must be justified**

| Violation | Why Needed | Simpler Alternative Rejected Because |
|-----------|------------|-------------------------------------|
| | | |

No violations — this feature simplifies the codebase by removing a special-cased code path.