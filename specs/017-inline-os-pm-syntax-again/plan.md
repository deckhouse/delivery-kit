# Implementation Plan: Inline os-pm Syntax (reverting 015)

**Branch**: `017-inline-os-pm-syntax-again` | **Date**: 2026-08-13 | **Spec**: `specs/017-inline-os-pm-syntax-again/spec.md`

**Input**: Feature specification from `specs/017-inline-os-pm-syntax-again/spec.md`

**Note**: This template is filled in by the `/speckit-plan` command.

## Summary

Restore `os-pm` package declaration to inline `spec: [pkg1, pkg2]` syntax while preserving multiple sections and per-section `env`. Keep os-pm SBOM collection metadata and runtime paths in the SBOM domain without introducing a dependency from `pkg/config` into container/SBOM implementation code; keep shared PM metadata in `pkg/sbom/os_pm/metadata` and expose the cataloger name through the config ecosystem entry in the same way as language package managers. Generate exported environment prefixes in the same shell command as `pm install`, remove os-pm-specific checksum input, keep the build SBOM step free of manual os-pm merging, and remove the obsolete `pm:lock` Taskfile task and its stale `AGENTS.md` documentation.

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

**PM metadata ownership invariant**: `ContainerFactoryIndexPath`, the container-factory version-file path, and the os-pm cataloger name are defined once in `pkg/sbom/os_pm/metadata`, which contains only dependency-free metadata and does not import `pkg/config`, SBOM collectors, or container backends. `pkg/sbom/packages/os_pm` owns runtime collection, while `pkg/config` consumes metadata without pulling in the collector implementation or redeclaring string values.

**Command environment invariant**: `PACKAGES_VERSION`, `REGISTRY`, and per-section user environment variables must be shell environment prefixes on the same command invocation as `pm install`. They must not be emitted as standalone assignments separated from `pm install` with `;`, because unexported shell variables are otherwise invisible to the child process. Assemble the install fragment with a readable formatting construct such as `fmt.Sprintf`, not `+` string concatenation.

**Version provenance invariant**: `PACKAGES_VERSION` is consumed while the package-install command runs inside the container and is persisted to `ContainerFactoryVersionPath`. SBOM collection does not read `PACKAGES_VERSION` from the host process; it reads the persisted version file from the image only. The runtime index is mandatory when os-pm processing is enabled. Version-read errors must be written to debug logging with image/path context, and the collector must preserve the agreed error contract.

**Scale/Scope**: Single binary CLI tool with ~30+ subcommands across build, deploy, cleanup, SBOM, and auxiliary domains

### Key Affected Subsystems

| Subsystem | Path | Nature of Change |
|-----------|------|------------------|
| Config parsing | `pkg/config/raw_packages_directive.go` | Restore inline `spec` list parsing for `os-pm`; skip `FileBasedSpec` for `os-pm` |
| Config model | `pkg/config/packages_directive.go` | Restore `PackagesSpec` with `Packages []string`; update `ecosystems` entry to reference `pkg/sbom/os_pm/metadata.CatalogerName`; update `validate()` |
| Command generation | `pkg/config/packages_commands.go` | Add `formatInstallCommand(pkgs)` emitting `pm install <pkgs>`; build prefix, env prefix, install command, and final command as separately readable steps; use PM path constants from `pkg/sbom/os_pm/metadata`; change `InstallCmd` callback signature |
| Stapel config | `pkg/config/stapel_image_base.go` | Remove `OSPMLockPath()`, `OSPMSpecPath()`; restore `HasOSPMPackages()` |
| Build phase | `pkg/build/build_phase.go` | Replace lock/spec paths with `hasOsPmPackages` bool; remove `PMBOMPatcher` creation |
| SBOM step | `pkg/build/sbom_step.go` | Remove inline os-pm BOM merge and os-pm checksum input; call the package-level SBOM operation through the existing pipeline |
| SBOM packages | `pkg/sbom/packages/os_pm/collect.go`, `pkg/sbom/os_pm/metadata/metadata.go` | Collect mandatory `/var/lib/pm/index.json` data before generic patchers; debug-log version-read errors; keep shared paths and cataloger name in the metadata subpackage |
| PMBOMPatcher | `pkg/sbom/packages/os_pm/pm_bom_patcher.go` | **DELETE** entire file — runtime collection supersedes it |
| Taskfile | `Taskfile.dist.yaml` | **DELETE** obsolete `pm:lock` task |
| SBOM managedinput | `pkg/sbom/managedinput/managedinput.go` | No change — already skips `os-pm` (FR-012) |
| Shared PM metadata | `pkg/sbom/os_pm/metadata/metadata.go` | Own paths/cataloger metadata near the os-pm domain without importing config, SBOM collection, or container backend code |
| Tests (unit) | `pkg/config/*_test.go`, `pkg/sbom/*_test.go`, `pkg/build/stage/packages_test.go` | Update from file-based to inline spec assertions; verify every command case with exact full-string expectations, readable command assembly, mandatory index behavior, debug logging, checksum inputs, and version-read errors |
| Tests (e2e) | `test/e2e/sbom/_fixtures/*` | Revert `pm.yaml`/`pm.lock` fixtures to inline spec; remove fixture files |
| Documentation | `AGENTS.md` | Remove stale `pm:lock` and lock-artifact instructions after Taskfile removal |

### Unchanged Subsystems

- `pkg/sbom/packages/os_pm/os_pm.go` — `ParsePmInstalledJSON` and `ConvertToCycloneDX` already parse flat JSON (correct for `/var/lib/pm/index.json` format)
- `pkg/sbom/packages/os_pm/os_pm_test.go` — test data already in flat format
- `pkg/sbom/managedinput/` — os-pm skip logic is already correct
- `pkg/build/stage/packages.go` — stage wiring is unchanged; commands are generated at config parse time
- `pkg/config/raw_stapel_image.go` — already calls `GeneratePackagesCommands` generically; no change needed

### Required SBOM ordering and verification work

The restored runtime-index path introduces os-pm components after the initial scan/merge phase. The implementation MUST keep collection and integration in `pkg/sbom/packages/os_pm`, and the returned final BOM must contain those components before `externalref.ExternalRefPatcher` runs. `pkg/build/sbom_step.go` must not append components or dependencies itself. The package-level API should make the ordering explicit while preserving `ErrExternalRefEnrich` propagation to the build phase.

The implementation plan also includes:

- no changes to `pkg/container_backend/docker_server_backend.go`; backend behavior is treated as an existing contract;
- removal of the redundant exported `ReadContainerFactoryVersion` wrapper, keeping version reading internal to the os-pm collector;
- a co-located unit regression test proving a component read by `CollectBOM` is visible to the PURL patcher and that `ErrExternalRefEnrich` propagates;
- an e2e regression test for mixed resolver outcomes across multiple images, including continued processing of successful images and hierarchical aggregation;
- explicit cache-path verification that the generic checksum remains stable for equivalent scan/merge/signing/platform inputs and does not encode an os-pm enablement flag; image identity remains the source of runtime-index changes;
- fixture verification that every expected failing component is actually present in the built image. In particular, `openssl` must either be supplied by the declared base/package state or be added explicitly to the fixture; the test must not assert a component that is not guaranteed to exist;
- command-generation verification that all required and user-provided environment variables appear as prefixes on the same shell command as `pm install`, including a negative assertion against the invalid `; pm install` form;
- full-string test verification for every env case in `pkg/config/packages_commands_test.go`, with no callback-based substring checks;
- checksum verification using genuinely different os-pm-enabled and os-pm-disabled states, or removal of the redundant assertion if the checksum contract is covered by a stronger test with distinct inputs;
- mandatory-index verification that an absent `/var/lib/pm/index.json` fails collection;
- version-file error verification that writes read failures to debug logging with image/path context and preserves the collector's error contract;
- dependency-graph verification that `pkg/config` consumes PM metadata through `pkg/sbom/os_pm/metadata` rather than importing the SBOM collector or container backend;
- exact command-output verification that every env case in `pkg/config/packages_commands_test.go` compares the complete returned string with `Equal(expected)`, including preamble, env ordering, separators, quoting, and package arguments;
- readable command-construction verification that `formatInstallCommand` forms a clearly named command prefix, a clearly named environment-prefix string, a clearly named install command, and then the final semicolon-joined command without opaque inline concatenation.

## Constitution Check

*GATE: Must pass before Phase 0 research. Re-check after Phase 1 design.*

**Constitutional Principles Applied**:

1. **I. Simplicity Over Abstraction** — PASS. Inline `spec: [curl, jq]` is simpler than file-based `pm.yaml`/`pm.lock`. Removing `PMBOMPatcher` and `FileBasedSpec` for os-pm reduces abstraction. The neutral PM metadata package must remain minimal and data-only; it is justified by avoiding an inappropriate dependency from config to SBOM/container implementation code. The `InstallCmd` callback pattern is preserved as it already exists.

2. **II. Go Idiomatic Code** — PASS. All public functions take `context.Context` first. Errors are wrapped with context. Guard clauses used for early validation (empty spec, workdir rejection).

3. **III. Minimal Public Surface** — PASS. Removing `OSPMLockPath()` and `OSPMSpecPath()` from `StapelImageBase` reduces the public API surface. Restoring `HasOSPMPackages()` as a boolean getter is minimal.

4. **IV. Test-Before-Merge** — PASS. All changed packages have existing Ginkgo test coverage. Tests will be updated to assert inline syntax behavior, exported env prefixes, final-BOM PURL enrichment, meaningful checksum input differences, version-read error handling, dependency ownership, and the mixed-outcome e2e scenario. The `managedinput` tests are unchanged.

5. **V. Conventional Commits** — PASS. Branch already follows convention.

### Post-Design Re-Evaluation (Phase 1 complete)

All gates re-checked after design artifact generation. No violations identified. The design now explicitly preserves the final-BOM ordering invariant: `CollectBOM` precedes external-reference enrichment, and tests cover both the direct unit contract and the e2e aggregation path.

- **Simplicity**: Design uses existing `interface{}` field for `Spec`, removes duplicate build-layer merge logic, removes obsolete lock-file tooling, avoids backend changes, removes the redundant version wrapper, and keeps only a minimal metadata subpackage near os-pm to prevent an architectural dependency inversion.
- **Go Idiomatic**: All new/restored functions follow Context-first convention. No named returns, no dot imports; command assembly exposes prefix, env, install, and final command stages as readable values, and tests verify complete outputs rather than substrings.
- **Public Surface**: Removed 2 methods (`OSPMLockPath`, `OSPMSpecPath`), restored 1 (`HasOSPMPackages`), removes the redundant exported version-reading wrapper, and exposes only the shared PM metadata required by config/SBOM integration through `pkg/sbom/os_pm/metadata`. No duplicate cross-domain constants are introduced.
- **Test Coverage**: All changed packages have Ginkgo tests identified, including meaningful checksum inputs, same-command env export, mandatory index behavior, debug-logged version-read failures, and dependency ownership. Research confirmed which tests need updates.
- **Commits**: Branch name is valid.

**Complexity Tracking**: No violations to justify. Simple revert-with-enhancements.

**Environment note**: `task test:setup:environment` has already been executed and the e2e/integration test environment is pre-configured. See the Environment Configuration section in `.specify/memory/constitution.md`. Do not skip e2e tests citing environment setup during implementation.

**Scope clarification**: This plan does not introduce or retain a `pm:lock` workflow. The obsolete `pm:lock` task in `Taskfile.dist.yaml` and its corresponding instructions in `AGENTS.md` are removed because inline os-pm syntax has no lock artifact. The config ecosystem must nevertheless retain a non-empty `CatalogerName`, sourced from `pkg/sbom/os_pm/metadata`, for consistency with language package managers and testability.

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
pkg/config/                             # Configuration parsing — significant changes
├── packages_directive.go               # Restore PackagesSpec, update ecosystems
├── packages_commands.go                # Add formatInstallCommand, change InstallCmd sig; preserve same-command env prefixes
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
├── collect.go                          # Collect mandatory index and debug-log version-read errors
├── pm_bom_patcher.go                   # DELETE
├── pm_bom_patcher_test.go              # DELETE
├── os_pm.go                            # Reuse parser/converter; expose only package-level runtime SBOM behavior
└── os_pm_test.go                       # No change needed

pkg/container_backend/docker_server_backend.go # No change; existing file-read contract is retained

pkg/sbom/os_pm/metadata/                 # PM metadata kept near the os-pm domain
└── metadata.go                           # Paths and cataloger name shared by config and SBOM domains

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