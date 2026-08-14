# Implementation Plan: Inline os-pm Syntax (reverting 015)

**Branch**: `017-inline-os-pm-syntax-again` | **Date**: 2026-08-13 | **Spec**: `specs/017-inline-os-pm-syntax-again/spec.md`

**Input**: Feature specification from `specs/017-inline-os-pm-syntax-again/spec.md`

**Note**: This template is filled in by the `/speckit-plan` command.

## Summary

Revert `os-pm` package declaration from the 015 file-based `pm.yaml`/`pm.lock` approach back to inline `spec: [pkg1, pkg2]` syntax while preserving the ability to have **multiple os-pm sections** per `packages` list (each with its own `env`). SBOM is collected from `/var/lib/pm/index.json` inside the built image after all pm commands execute, replacing the 015-era `PMBOMPatcher` that read `pm.lock` from the git commit.

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

**SBOM pipeline invariant**: `CollectBOM` must append the final os-pm components before the PURL external-reference patcher runs. Every component present in the final BOM, including components read from `/var/lib/pm/index.json`, must be eligible for PURL enrichment. A cache hit may bypass collection only when the stable SBOM checksum includes every input that can change the resulting BOM; otherwise the cache path must be reviewed or invalidated.

**Scale/Scope**: Single binary CLI tool with ~30+ subcommands across build, deploy, cleanup, SBOM, and auxiliary domains

### Key Affected Subsystems

| Subsystem | Path | Nature of Change |
|-----------|------|------------------|
| Config parsing | `pkg/config/raw_packages_directive.go` | Restore inline `spec` list parsing for `os-pm`; skip `FileBasedSpec` for `os-pm` |
| Config model | `pkg/config/packages_directive.go` | Restore `PackagesSpec` with `Packages []string`; update `ecosystems` entry; update `validate()` |
| Command generation | `pkg/config/packages_commands.go` | Add `formatInstallCommand(pkgs)` emitting `pm install <pkgs>`; change `InstallCmd` callback signature |
| Stapel config | `pkg/config/stapel_image_base.go` | Remove `OSPMLockPath()`, `OSPMSpecPath()`; restore `HasOSPMPackages()` |
| Build phase | `pkg/build/build_phase.go` | Replace `osPmLockPath`/`osPmSpecPath` with `hasOsPmPackages` bool; remove `PMBOMPatcher` creation |
| SBOM step | `pkg/build/sbom_step.go` | Change `osPmLockPath` param to `osPmEnabled` bool; collect os-pm BOM before applying PURL enrichment; inject `CollectBOM` result into the final BOM |
| SBOM packages | `pkg/sbom/packages/os_pm/collect.go` | Restore `CollectBOM()` reading `/var/lib/pm/index.json` from image |
| PMBOMPatcher | `pkg/sbom/packages/os_pm/pm_bom_patcher.go` | **DELETE** entire file — replaced by `CollectBOM` |
| SBOM managedinput | `pkg/sbom/managedinput/managedinput.go` | No change — already skips `os-pm` (FR-012) |
| Tests (unit) | `pkg/config/*_test.go`, `pkg/sbom/*_test.go`, `pkg/build/stage/packages_test.go` | Update from file-based to inline spec assertions |
| Tests (e2e) | `test/e2e/sbom/_fixtures/*` | Revert `pm.yaml`/`pm.lock` fixtures to inline spec; remove fixture files |

### Unchanged Subsystems

- `pkg/sbom/packages/os_pm/os_pm.go` — `ParsePmInstalledJSON` and `ConvertToCycloneDX` already parse flat JSON (correct for `/var/lib/pm/index.json` format)
- `pkg/sbom/packages/os_pm/os_pm_test.go` — test data already in flat format
- `pkg/sbom/managedinput/` — os-pm skip logic is already correct
- `pkg/build/stage/packages.go` — stage wiring is unchanged; commands are generated at config parse time
- `pkg/config/raw_stapel_image.go` — already calls `GeneratePackagesCommands` generically; no change needed

### Required SBOM ordering and verification work

The restored `CollectBOM` path introduces os-pm components after the initial scan/merge phase. The implementation MUST append those components before `externalref.ExternalRefPatcher` is applied; otherwise PURL resolution silently skips runtime-index components and `BuildPhase` cannot aggregate their `ErrExternalRefEnrich` failures. The preferred design is to collect and merge os-pm components first, then run all patchers against the resulting BOM. If preserving the existing go-mod patcher order requires a narrower change, at minimum the external-reference patcher must run after `CollectBOM`.

The implementation plan also includes:

- a co-located unit regression test proving a component read by `CollectBOM` is visible to the PURL patcher and that `ErrExternalRefEnrich` propagates;
- an e2e regression test for mixed resolver outcomes across multiple images, including continued processing of successful images and hierarchical aggregation;
- explicit cache-path verification so a previously generated SBOM cannot bypass the resolver test when the BOM inputs changed; the stable checksum and cache annotations must be checked against the final BOM inputs;
- fixture verification that every expected failing component is actually present in the built image. In particular, `openssl` must either be supplied by the declared base/package state or be added explicitly to the fixture; the test must not assert a component that is not guaranteed to exist.

## Constitution Check

*GATE: Must pass before Phase 0 research. Re-check after Phase 1 design.*

**Constitutional Principles Applied**:

1. **I. Simplicity Over Abstraction** — PASS. Inline `spec: [curl, jq]` is simpler than file-based `pm.yaml`/`pm.lock`. Removing `PMBOMPatcher` and `FileBasedSpec` for os-pm reduces abstraction. The `InstallCmd` callback pattern is preserved as it already exists.

2. **II. Go Idiomatic Code** — PASS. All public functions take `context.Context` first. Errors are wrapped with context. Guard clauses used for early validation (empty spec, workdir rejection).

3. **III. Minimal Public Surface** — PASS. Removing `OSPMLockPath()` and `OSPMSpecPath()` from `StapelImageBase` reduces the public API surface. Restoring `HasOSPMPackages()` as a boolean getter is minimal.

4. **IV. Test-Before-Merge** — PASS. All changed packages have existing Ginkgo test coverage. Tests will be updated to assert inline syntax behavior, final-BOM PURL enrichment, cache behavior, and the mixed-outcome e2e scenario. The `managedinput` tests are unchanged.

5. **V. Conventional Commits** — PASS. Branch already follows convention.

### Post-Design Re-Evaluation (Phase 1 complete)

All gates re-checked after design artifact generation. No violations identified. The design now explicitly preserves the final-BOM ordering invariant: `CollectBOM` precedes external-reference enrichment, and tests cover both the direct unit contract and the e2e aggregation path.

- **Simplicity**: Design uses existing `interface{}` field for `Spec` instead of adding new struct fields — minimal diff. `PMBOMPatcher` removal reduces code.
- **Go Idiomatic**: All new/restored functions follow Context-first convention. No named returns, no dot imports.
- **Public Surface**: Removed 2 methods (`OSPMLockPath`, `OSPMSpecPath`), restored 1 (`HasOSPMPackages`). Net reduction.
- **Test Coverage**: All changed packages have Ginkgo tests identified. Research confirmed which tests need updates.
- **Commits**: Branch name is valid.

**Complexity Tracking**: No violations to justify. Simple revert-with-enhancements.

**Environment note**: `task test:setup:environment` has already been executed and the e2e/integration test environment is pre-configured. See the Environment Configuration section in `.specify/memory/constitution.md`. Do not skip e2e tests citing environment setup during implementation.

## Project Structure

### Documentation (this feature)

```text
specs/017-inline-os-pm-syntax-again/
├── plan.md              # This file (speckit-plan command output)
├── spec.md              # Feature specification
├── research.md          # Phase 0 output
├── data-model.md        # Phase 1 output
├── quickstart.md        # Phase 1 output
├── contracts/           # Phase 1 output
└── tasks.md             # Phase 2 output (speckit-tasks command - NOT created by speckit-plan)
```

### Source Code (repository root)

```text
pkg/config/                             # Config parsing — significant changes
├── packages_directive.go               # Restore PackagesSpec, update ecosystems
├── packages_commands.go                # Add formatInstallCommand, change InstallCmd sig
├── raw_packages_directive.go           # Restore inline spec list parsing
├── stapel_image_base.go                # Remove OSPMLockPath/SpecPath, restore HasOSPMPackages
├── raw_stapel_image.go                 # No change needed
├── raw_packages_directive_test.go      # Update test data
├── packages_directive_javascript_test.go # Update test data
├── packages_commands_test.go           # Update test assertions
└── stapel_image_base_test.go           # Update test assertions

pkg/build/                              # Build pipeline — moderate changes
├── build_phase.go                      # Replace OSPMLockPath/SpecPath with HasOSPMPackages
├── sbom_step.go                        # Replace osPmLockPath with osPmEnabled bool; collect before PURL enrichment

pkg/sbom/packages/os_pm/                # SBOM collection — significant changes
├── collect.go                          # Restore CollectBOM reading /var/lib/pm/index.json
├── pm_bom_patcher.go                   # DELETE
├── pm_bom_patcher_test.go              # DELETE
├── os_pm.go                            # No change needed
└── os_pm_test.go                       # No change needed

pkg/build/stage/
└── packages_test.go                    # Update test data

test/e2e/sbom/_fixtures/                # Revert fixtures to inline syntax
├── *pm.yaml                            # DELETE
└── *pm.lock                            # DELETE
```

## Complexity Tracking

> No constitutional violations. All changes are straightforward reversions of 015 with enhancements (env support per-section, `containerFactoryVersion` from env or file).

| Violation | Why Needed | Simpler Alternative Rejected Because |
|-----------|------------|-------------------------------------|
| (none) | — | — |