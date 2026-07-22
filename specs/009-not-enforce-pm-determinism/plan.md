# Implementation Plan: Not Enforce pm Determinism

**Branch**: `feat/config/not-enforce-pm-determinism` | **Date**: 2026-07-22 | **Spec**: `specs/009-not-enforce-pm-determinism/spec.md`

**Input**: Feature specification from `/specs/009-not-enforce-pm-determinism/spec.md`

**Note**: This feature builds on the `006-enforce-pm-determinism` revert but improves the implementation by unifying `os-pm` into the `PackageEcosystem` registry (extended to support inline package lists). SBOM state is read from `/var/lib/pm/index.json` (maintained by `pm` itself) via `ReadFileFromImage` — no separate capture command is needed.

## Summary

Refactor `os-pm` from a special-cased package type back into the unified `PackageEcosystem` registry by extending the registry to support both file-based ecosystems (using `DefaultSpecFile`/`DefaultLockFile`) and inline-package-list ecosystems (using `PackagesSpec` with inline package names). The `os-pm` type uses `spec: [curl==8.12.1, jq]` syntax instead of file-based spec/lock files. A composite command is generated that: (1) creates `/var/lib/pm/` directory, (2) resolves `PACKAGES_VERSION` from secret/env and writes it to `/var/lib/pm/container-factory-version`, (3) runs resolved `PACKAGES_VERSION=<...> REGISTRY=<...> pm install <pkg_1> <pkg_2> ...`. SBOM state is read from `/var/lib/pm/index.json` (maintained by `pm` itself) via `ReadFileFromImage` — no separate capture command is needed.

## Technical Context

**Language/Version**: Go 1.24.10

**Primary Dependencies**:
- **Container building**: `containers/buildah` (werf fork: `werf/3p-buildah`), `containers/storage`, `containers/image`
- **SBOM**: `CycloneDX/cyclonedx-go`, `facebookincubator/nvdtools`
- **Utilities**: `samber/lo`, `werf/common-go`, `go-git/go-git`

**Storage**: OCI container registry (Docker v2, ECR), local git repository, Buildah container storage

**Testing**: Ginkgo + Gomega for unit tests and e2e tests

**Target Platform**: Linux (amd64/arm64) via Buildah

**Project Type**: CLI tool (Go binary via `cmd/werf/main.go`)

**Performance Goals**: No performance impact — the revert changes the package installation mechanism but does not affect throughput.

**Constraints**:
- `workdir` field MUST NOT be configurable for `os-pm` directives
- `PackageEcosystem` struct SHALL be simplified: `DefaultSpec` → `DefaultSpecFile`, `DefaultLock` → `DefaultLockFile`, `InstallCmd func(workdir, specFile string, specList []string) string` — single function handles all ecosystem types
- `os-pm` SHALL be added to the `ecosystems` registry with its own `InstallCmd` that encapsulates environment setup and package installation
- `PackagesSpec` struct with `Packages []string` SHALL be used for `os-pm` instead of `FileBasedSpec`
- `GeneratePackagesCommands()` SHALL call `eco.InstallCmd()` for ALL ecosystem types uniformly — no special-casing for `os-pm`
- SBOM state SHALL be read from `/var/lib/pm/index.json` (a file `pm` writes itself) via `ReadFileFromImage` — no separate capture command needed
- `os-pm` InstallCmd SHALL produce a composite command: (1) create `/var/lib/pm/` directory, (2) resolve `PACKAGES_VERSION` (with fallback to `/run/secrets/PACKAGES_VERSION`) and write it to `/var/lib/pm/container-factory-version` with a guard requiring the variable to be non-empty, (3) resolve `REGISTRY` and `PACKAGES_VERSION` as inline env var templates and run `pm install <pkg_1> <pkg_2> ...`; each `envVarTmpl(name string) string` generates an env var template `name="${name:-$(<cat> /run/secrets/<name> 2>/dev/null || true)}"` using `stapel.CatBinPath()` — no separate composer/prefix-joiner function is needed since the three command segments (mkdir, version file, install) are composed as a single `;`-separated shell command
- Constants SHALL be defined in `packages_commands.go`: `ContainerFactoryVersionDir = "/var/lib/pm"`, `ContainerFactoryVersionFile = ContainerFactoryVersionDir + "/container-factory-version"`, `ContainerFactoryVersionIndexFile = ContainerFactoryVersionDir + "/index.json"`
- `ContainerFactoryVersionSnapshotCmd()` SHALL be removed — the version file is now written as part of the `os-pm` InstallCmd itself

**Scale/Scope**: Single binary CLI tool. Change affects config parsing, package command generation, build phase integration, and SBOM collection for the `os-pm` type only.

## Constitution Check

*GATE: Must pass before Phase 0 research. Re-check after Phase 1 design.*

### Gates

| Gate | Constitution Rule | Assessment | Justification |
|------|-------------------|------------|---------------|
| G1: Simplicity Over Abstraction | I. Prefer stupid and simple over abstract and extendable | ✅ PASS | Extending `PackageEcosystem` with inline-package-list fields keeps `os-pm` in the unified registry, eliminating special-casing throughout the codebase. Simpler than the previous special-cased approach. |
| G2: Minimal Public Surface | III. Keep everything private/internal as much as possible | ✅ PASS | The unified approach keeps everything internal. The `PackageEcosystem` struct is already internal. |
| G3: Test-Before-Merge | IV. Tests MUST use Ginkgo + Gomega | ✅ PASS | All tests use Ginkgo + Gomega. The unified approach eliminates type-based special-casing in tests. |
| G4: No unnecessary abstractions | I. Minimize interfaces, generics, and embedding | ✅ PASS | Adding boolean flags and an optional command field to `PackageEcosystem` is the minimal extension needed to support inline-package-list ecosystems without special-casing. |

**No violations found. All gates pass.**

## Project Structure

### Documentation (this feature)

```text
specs/009-not-enforce-pm-determinism/
├── spec.md              # Feature specification
├── plan.md              # This file (implementation plan)
├── research.md          # Phase 0 research output
├── data-model.md        # Phase 1 data model design
├── quickstart.md        # Phase 1 validation guide
├── contracts/           # Phase 1 interface contracts
└── tasks.md             # Task list (created by /speckit-tasks)
```

### Source Code (changed files)

```text
pkg/config/
├── packages_directive.go           # Simplify PackageEcosystem: unified InstallCmd(workdir, specFile, specList), restore PackagesSpec, add os-pm to ecosystems registry
├── packages_commands.go            # Simplify to uniform eco.InstallCmd(workdir, specFile, specList) call for ALL types; env var template constuctor envVarTmpl(name string) string; os-pm command composition (formatMkdirCommand, formatVersionFileCommand, formatInstallCommand); constants ContainerFactoryVersionDir/File/IndexFile; remove ContainerFactoryVersionSnapshotCmd()
├── packages_commands_test.go       # Unit tests for envVarTmpl and os-pm command generation
├── raw_packages_directive.go       # Update fillFileBasedSpec() to special-case os-pm (parse spec as list) vs file-based (parse spec as string)
├── raw_packages_directive_test.go  # Update tests for os-pm inline spec list
├── stapel_image_base.go            # Remove OSPMLockPath(), keep HasOSPMPackages()
└── helpers_test.go                 # No changes expected

pkg/build/
├── build_phase.go                  # Replace osPmLockPath string with hasOsPmPackages bool
└── sbom_step.go                    # Replace osPmLockPath string with osPmEnabled bool in ConvergeWithMerge

pkg/sbom/packages/os_pm/
├── os_pm.go                        # Rename ParsePmLockJSON → ParsePmInstalledJSON, remove pmLockFile struct
├── collect.go                      # Replace collectPacketsFromLock with collectInstalledPackets, read `/var/lib/pm/index.json` via ReadFileFromImage
├── os_pm_test.go                   # Update test references

test/e2e/sbom/
├── packages_test.go                # Update expectations for inline model
├── lifecycle_test.go               # Update expectations
├── gost_test.go                    # Update expectations
├── stage_dependencies_test.go      # Update expectations
└── _fixtures/                    # Remove pm.yaml/pm.lock files from all fixture directories; restore explicit version constraints (e.g., curl==8.12.1, jq==1.8.1, yq==4.48.1, tini==0.19.0, demo-app==1.0.0) from removed pm.yaml files into inline spec: list in werf.yaml
```

## Complexity Tracking

| Violation | Why Needed | Simpler Alternative Rejected Because |
|-----------|------------|-------------------------------------|
| N/A | Feature is a revert — it removes complexity, not adds it | — |
