# Implementation Plan: Inline os-pm Syntax (reverting 015)

**Branch**: `017-inline-os-pm-syntax-again` | **Date**: 2026-08-13 | **Spec**: `specs/017-inline-os-pm-syntax-again/spec.md`

**Input**: Feature specification from `specs/017-inline-os-pm-syntax-again/spec.md`

**Note**: This template is filled in by the `/speckit-plan` command.

## Summary

Restore `os-pm` package declaration to inline `spec: [pkg1, pkg2]` syntax while preserving multiple sections and per-section `env`. Keep all os-pm SBOM collection and runtime-index details inside `pkg/sbom/packages/os_pm`; the build SBOM step should invoke the package-level operation without merging os-pm components itself. Remove os-pm-specific checksum input, move the cataloger name and runtime-index path constants into the SBOM package, and remove the obsolete `pm:lock` Taskfile task.

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

**SBOM pipeline invariant**: os-pm runtime-index collection and BOM integration must remain encapsulated in `pkg/sbom/packages/os_pm`; the build layer must not duplicate component/dependency merge logic. Every runtime-index component must still be present before PURL external-reference enrichment. The stable SBOM checksum contains generic scan, merge, signer, and platform inputs only; os-pm enablement is not a separate checksum input because the built image digest is the source identity.

**Scale/Scope**: Single binary CLI tool with ~30+ subcommands across build, deploy, cleanup, SBOM, and auxiliary domains

### Key Affected Subsystems

| Subsystem | Path | Nature of Change |
|-----------|------|------------------|
| Config parsing | `pkg/config/raw_packages_directive.go` | Restore inline `spec` list parsing for `os-pm`; skip `FileBasedSpec` for `os-pm` |
| Config model | `pkg/config/packages_directive.go` | Restore `PackagesSpec` with `Packages []string`; update `ecosystems` entry; update `validate()` |
| Command generation | `pkg/config/packages_commands.go` | Add `formatInstallCommand(pkgs)` emitting `pm install <pkgs>`; change `InstallCmd` callback signature |
| Stapel config | `pkg/config/stapel_image_base.go` | Remove `OSPMLockPath()`, `OSPMSpecPath()`; restore `HasOSPMPackages()` |
| Build phase | `pkg/build/build_phase.go` | Replace lock/spec paths with `hasOsPmPackages` bool; remove `PMBOMPatcher` creation |
| SBOM step | `pkg/build/sbom_step.go` | Remove inline os-pm BOM merge and os-pm checksum input; call the package-level SBOM operation through the existing pipeline |
| SBOM packages | `pkg/sbom/packages/os_pm/collect.go` | Own the runtime-index path and cataloger name; collect and integrate `/var/lib/pm/index.json` data before generic patchers |
| PMBOMPatcher | `pkg/sbom/packages/os_pm/pm_bom_patcher.go` | **DELETE** entire file — runtime collection supersedes it |
| Taskfile | `Taskfile.dist.yaml` | **DELETE** obsolete `pm:lock` task |
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

The restored runtime-index path introduces os-pm components after the initial scan/merge phase. The implementation MUST keep collection and integration in `pkg/sbom/packages/os_pm`, and the returned final BOM must contain those components before `externalref.ExternalRefPatcher` runs. `pkg/build/sbom_step.go` must not append components or dependencies itself. The package-level API should make the ordering explicit while preserving `ErrExternalRefEnrich` propagation to the build phase.

The implementation plan also includes:

- a co-located unit regression test proving a component read by `CollectBOM` is visible to the PURL patcher and that `ErrExternalRefEnrich` propagates;
- an e2e regression test for mixed resolver outcomes across multiple images, including continued processing of successful images and hierarchical aggregation;
- explicit cache-path verification that the generic checksum remains stable for equivalent scan/merge/signing/platform inputs and does not encode an os-pm enablement flag; image identity remains the source of runtime-index changes;
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

- **Simplicity**: Design uses existing `interface{}` field for `Spec`, keeps os-pm details in its domain package, removes duplicate build-layer merge logic, and deletes obsolete lock-file tooling.
- **Go Idiomatic**: All new/restored functions follow Context-first convention. No named returns, no dot imports.
- **Public Surface**: Removed 2 methods (`OSPMLockPath`, `OSPMSpecPath`), restored 1 (`HasOSPMPackages`), and keeps new os-pm constants/functions scoped to the SBOM package. Net reduction in cross-domain surface.
- **Test Coverage**: All changed packages have Ginkgo tests identified. Research confirmed which tests need updates.
- **Commits**: Branch name is valid.

**Complexity Tracking**: No violations to justify. Simple revert-with-enhancements.

**Environment note**: `task test:setup:environment` has already been executed and the e2e/integration test environment is pre-configured. See the Environment Configuration section in `.specify/memory/constitution.md`. Do not skip e2e tests citing environment setup during implementation.

**Scope clarification**: This plan does not introduce or retain a `pm:lock` workflow. The obsolete `pm:lock` task in `Taskfile.dist.yaml` is removed because inline os-pm syntax has no lock artifact.

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
├── sbom_step.go                        # Remove inline os-pm merge and os-pm checksum input; call SBOM package operation

pkg/sbom/packages/os_pm/                # SBOM collection — significant changes
├── collect.go                          # Own constants and collect/integrate /var/lib/pm/index.json
├── pm_bom_patcher.go                   # DELETE
├── pm_bom_patcher_test.go              # DELETE
├── os_pm.go                            # Reuse parser/converter; expose only package-level runtime SBOM behavior
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