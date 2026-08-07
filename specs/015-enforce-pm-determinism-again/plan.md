# Implementation Plan: os-pm File-Based Syntax

**Branch**: `015-enforce-pm-determinism-again` | **Date**: 2026-08-05 | **Spec**: [spec.md](spec.md)

**Input**: Feature specification from `/specs/015-enforce-pm-determinism-again/spec.md`

**Note**: This template is filled in by the `/speckit-plan` command. See `.specify/templates/plan-template.md` for the execution workflow.

## Summary

The `os-pm` package type in werf currently uses an inline syntax where OS packages are declared as a list of strings in `werf.yaml` (e.g., `spec: [curl==8.12.1, jq]`). This feature replaces the inline syntax with a file-based syntax using `pm.yaml` (spec file) and `pm.lock` (lock file) at the repository root — consistent with how Go, Rust, Python, JavaScript, and other package types are handled. Key changes: register `os-pm` in the ecosystems registry with `DefaultSpecFile: "pm.yaml"` and `DefaultLockFile: "pm.lock"`; use `pm sync --from <lockfile>` as the install command (preceded by container factory version preamble command for SBOM purl qualifier); remove the special-cased `os-pm` branches in `fillFileBasedSpec()` and `validate()`; remove the now-unused `PackagesSpec` struct; reject `workdir` for `os-pm`; wire up SBOM cataloging for `pm.yaml`/`pm.lock` via the `CatalogerName` field. All unit and e2e tests referencing the old inline syntax must be migrated to the new file-based syntax — including e2e fixture `werf.yaml` files (stage_deps, stage_deps_file, type_change, and all inject/negative/regression fixtures).

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
- **`pkg/config/packages_commands.go`** — `GeneratePackagesCommands()` needs no changes (already uses `eco.InstallCmd`). The container factory version preamble functions (`formatMkdirCommand()`, `formatVersionFileCommand()`) and constants (`ContainerFactoryVersionDir`, `ContainerFactoryVersionFile`) are KEPT — FR-002 requires them for SBOM purl qualifier. `ContainerFactoryVersionIndexFile` constant may be removed (only used by dead runtime-index code in `os_pm/collect.go`).
- **`pkg/sbom/packages/os_pm/`** — **Package is partially dead code** (previously fully dead, but re-evaluated based on updated spec):
  - `collect.go`: `collectInstalledPackets()` — reads runtime index (`ContainerFactoryVersionIndexFile`) from inside image — DEAD (per FR-010b, no package data from inside built image). `readContainerFactoryVersion()` — reads `ContainerFactoryVersionFile` for purl qualifier — KEPT (per FR-010b). `CollectBOM()` — orchestrator, needs rework to remove the `collectInstalledPackets()` call.
  - `os_pm.go`: `ParsePmLock()` — **NOT DEAD** (per FR-017 and spec clarification: reused to read `pm.lock` from build context — `pm.lock` has same format as `/var/lib/pm/index.json`). `collectPacketsFromLock()` — **NOT DEAD** (reused for `pm.lock` per FR-017). `ConvertToCycloneDX()`, `PmPackageInfo`, helper functions — may still be needed for pm.lock-to-CycloneDX conversion; otherwise DEAD.
  - `os_pm_test.go`, `suite_test.go`, `testdata/` — test code for dead functions needs removal or rewriting.
- **`pkg/sbom/managedinput/managedinput.go`** — `buildResolvers()` skips ecosystems with empty `CatalogerName`; once `os-pm` has a `CatalogerName`, it automatically gets a cataloger with source paths `pm.yaml` and `pm.lock` at the repository root
- **`pkg/build/build_phase.go`** — Change `convergeImageSbom()` from boolean flag to lock file path string: extract `OSPMLockPath()` from `StapelImageBase` and pass as `osPmLockPath` to `ConvergeWithMerge()` instead of the `hasOsPmPackages` boolean.
- **`pkg/sbom/packages/os_pm/pm_bom_patcher.go`** — New file implementing the PM BOMPatcher. Reads container factory version from inside the built image via `readContainerFactoryVersion()` (reuses `collect.go`), finds PM components by `syft:package:foundBy = "os-pm-lock-cataloger"`, and appends `containerFactoryVersion=<version>` PURL qualifier.
- **`pkg/build/sbom_step.go`** — Change `ConvergeWithMerge()` signature: replace `osPmEnabled bool` with `osPmLockPath string`. Wire the PM BOMPatcher from `pkg/sbom/packages/os_pm/pm_bom_patcher.go` into the patchers list.
- **Unit test files** — `packages_directive_*_test.go`, `raw_packages_directive_test.go`, `packages_commands_test.go`, `managedinput_test.go`, `packages_test.go` all reference the old inline `os-pm` syntax and need updating
- **E2E test files** — `test/e2e/sbom/packages_test.go`, `gost_test.go`, `lifecycle_test.go`, `stage_dependencies_test.go` reference inline `os-pm` syntax and need updating
- **E2E fixtures** — 16 `werf.yaml` fixtures under `test/e2e/sbom/_fixtures/` use inline `spec: [pkg...]` syntax that must be migrated to file-based `pm.yaml`/`pm.lock`

### Updates from Spec Change (2026-08-05)

The spec was updated with:
1. **Clarification reversed**: The container factory version file write command IS still required — FR-002 now states "The container factory version file write command SHALL be emitted before `pm sync` (preserving existing behavior)" for the SBOM purl qualifier.
2. **FR-010b nuanced**: Component metadata is from `pm.lock` (no runtime index), BUT `ContainerFactoryVersionFile` SHALL still be read from inside the built image for the purl qualifier.
3. **New FR-016**: Explicit requirement to migrate specific e2e fixture groups (stage_deps, stage_deps_file, type_change) with concrete file paths.
4. **New success criteria**:
   - **SC-013**: All e2e test fixtures are migrated to file-based `pm.yaml`/`pm.lock` syntax and corresponding e2e tests pass.
   - **SC-014**: The `stage_deps_file` e2e test tracks `pm.yaml` and `pm.lock` via `git.stageDependencies.packages` and demonstrates that changes to either file trigger SBOM regeneration.

**Consequence**: `formatMkdirCommand()`, `formatVersionFileCommand()`, `ContainerFactoryVersionDir`, `ContainerFactoryVersionFile` must be KEPT. Only `ContainerFactoryVersionIndexFile`, `collectInstalledPackets()`, and `ParsePmLock()` (the runtime index reader) are dead.

### E2E Test Fixtures Requiring Migration

FR-016 explicitly lists the following fixture groups for migration to file-based `pm.yaml`/`pm.lock`:

| Fixture Group | States | Key Action |
|---------------|--------|------------|
| `inject/ospm_basic` | — | Replace inline `spec: [curl==8.12.1]` with `pm.yaml` + `pm.lock` |
| `inject/ospm_gost_override` | — | Same migration |
| `inject/ospm_scratch_secrets` | — | Same migration |
| `stage_deps` | 0, 1, 2 | Replace inline `spec: [jq==1.8.1]` with `pm.yaml` + `pm.lock` |
| `stage_deps_file` | 0, 1 | Replace inline `spec: [jq==1.8.1]` with `pm.yaml` + `pm.lock`; update `stageDependencies.packages` to track `pm.yaml`/`pm.lock` instead of `versions.txt` |
| `type_change` | 0 | Replace inline `spec: [jq==1.8.1]` with `pm.yaml` + `pm.lock` |
| `packages_merge/base_with_child` | — | Replace inline `spec:` with `pm.yaml` + `pm.lock` |
| `packages_merge/parent_propagation` | — | Same migration |
| `lifecycle/multi_image` | — | Same migration |
| `purl_resolver_errors` | — | Same migration |
| `negative/broken_pm` | — | Same migration |
| `negative/no_pm_binary` | — | Same migration |
| `regressions/manifest_annotation` | — | Same migration |

All fixtures must also create `pm.lock` via `pm lock --from=pm.yaml`.

### Unknowns

1. **Build phase lock path propagation (FR-011)** — `convergeImageSbom()` in `pkg/build/build_phase.go` currently extracts `OSPMLockPath()` and reduces it to a boolean (`hasOsPmPackages`). Per FR-011, the lock file path must be propagated as a string to `ConvergeWithMerge()` in `pkg/build/sbom_step.go` instead of a boolean flag. The build phase then passes the lock path to the PM BOMPatcher which enriches host-scanned PM components with the container factory version qualifier.
2. **Test fixture locations** — All unit test YAML fixtures/data referencing inline `os-pm` syntax and all e2e fixtures need updating. FR-016 provides a concrete list.
3. **Git stage dependencies behavior** — Already supported for all package types per FR-013, but verify there's no `os-pm` specific exclusion.
4. **Build phase command wiring** — Trace how the build phase generates and runs `pm sync` commands from `GeneratePackagesCommands()`. The command includes the container factory version preamble (per FR-002): `mkdir -p /var/lib/pm` and container factory version file write before `pm sync --from <lockfile>`.  
5. **PM PURL enrichment** — After host-scanning `pm.lock` via the Syft cataloger, PM components lack the `containerFactoryVersion` PURL qualifier. A dedicated `BOMPatcher` reads this version from inside the built image and enriches the host-scanned PM components. The patcher is added to the `patchers` list in `convergeImageSbom()` and invoked during SBOM merge in `ConvergeWithMerge()`.

## Constitution Check

*GATE: Must pass before Phase 0 research. Re-check after Phase 1 design.*

| Principle | Check | Status |
|-----------|-------|--------|
| **I. Simplicity Over Abstraction** | Removing a special-cased inline syntax in favor of the standard `FileBasedSpec` path reduces complexity — one less code branch, one less struct (`PackagesSpec`), consistent with all other package types. | ✅ PASS |
| **II. Go Idiomatic Code** | No changes to public API signatures beyond the optional `HasOSPMPackages()` → `OSPMLockPath()` rename. | ✅ PASS |
| **III. Minimal Public Surface** | The change shrinks the public surface by removing `PackagesSpec` and the special-cased `os-pm` validation/parsing branches. | ✅ PASS |
| **IV. Test-Before-Merge** | All unit test fixtures/assertions using inline `os-pm` syntax must be updated. All 16 e2e fixtures must be migrated to file-based `pm.yaml`/`pm.lock` syntax. The corresponding e2e Go test files referencing inline syntax must also be updated. | ⚠️ PASS with conditions |
| **V. Conventional Commits** | Standard commit format applies. No unusual patterns. | ✅ PASS |

**GATE (post-Phase 1 re-evaluation)**: No violations — proceed to Phase 2.

The design artifacts (research.md, data-model.md, contracts/, quickstart.md) have been generated. The e2e fixture migration requirement is substantial but mechanical, and does not change the core design approach.

## Project Structure

### Documentation (this feature)

```text
specs/015-enforce-pm-determinism-again/
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