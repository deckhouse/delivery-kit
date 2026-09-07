# Implementation Plan: Alternative Language Package Managers

**Branch**: `022-alternative-language-package-managers` | **Date**: 2026-09-07 | **Spec**: [spec.md](spec.md)

**Input**: Feature specification from `/specs/022-alternative-language-package-managers/spec.md`

## Summary

Add ephemeral global bootstrap support for Yarn, pnpm, uv, and Poetry in file-based `packages` directives. Each directive receives a required exact `version`, rejects a pre-existing alternative manager, installs the manager globally through npm or pip, performs the existing frozen dependency installation, and removes only the temporary global manager package after success. The implementation extends the existing `pkg/config` ecosystem registry and package-stage command generation, preserving current primary-manager and SBOM behavior.

## Technical Context

**Language/Version**: Go 1.24.10

**Primary Dependencies**: Existing werf Go dependencies; no new external dependencies planned. Package managers remain external tools invoked inside the builder image through existing shell-stage execution.

**Storage**: Existing Buildah/container backend stage filesystem and package-stage cache. No new persistent storage.

**Testing**: Ginkgo + Gomega unit tests alongside `pkg/config` and `pkg/build/stage`; existing SBOM e2e suites for Yarn, pnpm, uv, and Poetry.

**Target Platform**: Linux container builds; Docker-backed e2e scenarios and prepared Buildah-capable environment.

**Project Type**: Go CLI tool with YAML configuration, container image build stages, and SBOM generation.

**Performance Goals**: Preserve package-stage caching; manager version and lifecycle commands must participate in the existing package-stage checksum. Do not add an extra build stage or independent lock scan.

**Constraints**: No new dependency; no change to primary package types; POSIX shell commands available through the existing Stapel builder; preserve frozen lock semantics and managed-input SBOM source paths; cleanup only on successful dependency installation.

**Scale/Scope**: Four alternative types (`javascript-yarn`, `javascript-pnpm`, `python-uv`, `python-poetry`) and four existing dedicated e2e scenarios. Other ecosystems are unchanged.

## Constitution Check

*GATE: Must pass before Phase 0 research. Re-check after Phase 1 design.*

- **I. Simplicity Over Abstraction — PASS.** Extend existing directive/registry and command-generation paths; do not introduce a new interface or build stage.
- **II. Go Idiomatic Code — PASS.** Keep public API changes minimal, use existing context-aware build APIs, guard validation early, and wrap new errors with operation context.
- **III. Minimal Public Surface — PASS.** `version` is a narrow per-directive field; lifecycle helpers remain internal.
- **IV. Test-Before-Merge — PASS.** Add co-located Ginkgo/Gomega tests and exercise all four manager e2e scenarios.
- **V. Conventional Commits — PASS.** No commit or branch operation is part of this plan; the active branch is already named according to the project convention.
- **Dependency rule — PASS.** No external dependency is added.
- **Code boundaries — PASS.** Configuration and build logic stay in `pkg/config` and `pkg/build`; e2e changes stay in `test/e2e/sbom`; documentation changes are limited to package-directive docs if required by implementation.

## Project Structure

### Documentation (this feature)

```text
specs/022-alternative-language-package-managers/
├── plan.md
├── research.md
├── data-model.md
├── quickstart.md
└── contracts/
    ├── configuration.md
    └── build-and-sbom.md
```

### Source Code (planned change areas)

```text
pkg/config/
├── packages_directive.go       # version field, alternative-manager metadata, validation
├── raw_packages_directive.go   # YAML version parsing and validation wiring
├── packages_commands.go        # bootstrap/install/cleanup command generation
└── *_test.go                   # config and command coverage

pkg/build/stage/
├── packages.go                 # package-stage behavior/checksum integration if needed
└── packages_test.go             # stage-level coverage if needed

test/e2e/sbom/
├── yarn_test.go
├── pnpm_test.go
├── uv_test.go
├── poetry_test.go
└── _fixtures/inject/{yarn_simple,pnpm_simple,uv_simple,poetry_simple}/
    ├── werf.yaml                 # exact manager versions
    └── Dockerfile.builder-base    # primary manager only; alternative absent

docs/
└── package-directive references # document version field and supported alternatives
```

**Structure Decision**: Reuse the existing monolith CLI boundaries. Keep manager-specific metadata in the existing `PackageEcosystem` registry. Add `InstallAlternativeManagerCmd` and `CleanupAlternativeManagerCmd` callback fields beside `InstallCmd`; each alternative ecosystem implements those callbacks, and its `InstallCmd` invokes them to assemble one directive-local shell sequence. Do not add a package-manager service, interface hierarchy, persistent state, or new stage.

## Phase 0: Research Summary

Research is recorded in [research.md](research.md). Key resolved decisions:

1. YAML field name is `version`, stored as a string and validated as exact `X.Y.Z` for alternative types.
2. npm bootstraps Yarn/pnpm; pip bootstraps uv/Poetry.
3. Bootstrap, frozen dependency install, and successful cleanup are one ordered package-stage sequence.
4. Existing lock flags, package-stage checksum, managed-input catalogers, and SBOM source paths remain authoritative.
5. Existing four alternative-manager e2e scenarios are the dedicated acceptance coverage; their fixtures need exact versions and must omit preinstalled alternatives.

## Phase 1: Design Summary

- Data model and state transitions are in [data-model.md](data-model.md).
- YAML/build/SBOM contracts are in [contracts/configuration.md](contracts/configuration.md) and [contracts/build-and-sbom.md](contracts/build-and-sbom.md).
- Runnable validation scenarios are in [quickstart.md](quickstart.md).

### Implementation sequencing

1. Extend raw and typed package directive models with `Version`; apply defaults without changing existing spec/lock behavior.
2. Add early validation for required exact versions on the four alternative types and reject version on primary/other types.
3. Extend `PackageEcosystem` with `InstallAlternativeManagerCmd` and `CleanupAlternativeManagerCmd` callbacks beside `InstallCmd`; retain existing install commands and environment handling.
4. Make each alternative `InstallCmd` call the two callbacks in order around the frozen dependency install: pre-existing-manager check, global npm/pip bootstrap, existing install command through the global executable, then global package cleanup on success. Ensure errors remain operation-specific and command content affects package-stage caching.
5. Add focused Ginkgo/Gomega tests for parsing, invalid versions, generated commands, failure ordering, cleanup, primary types, and multiple directives.
6. Update the four existing SBOM e2e fixtures/tests with exact versions and absence/cleanup assertions; retain existing dependency SBOM assertions.
7. Update package-directive reference documentation for the new required field and examples in supported languages, without modifying generated release files.

## Constitution Check (Post-Design)

- **Simplicity — PASS:** no new abstraction layer; one existing registry and one existing package stage.
- **Idiomatic Go — PASS:** typed field and internal helpers follow current config/command patterns; errors include operation context.
- **Minimal surface — PASS:** only the per-directive `version` configuration field is user-visible.
- **Testing — PASS:** unit and e2e coverage directly maps to every manager and failure lifecycle.
- **Dependencies and boundaries — PASS:** no new dependency and no cross-layer inversion.
- **Quality gates — PASS:** implementation validation follows the repository-required `task` commands and scoped e2e commands in `quickstart.md`.

## Complexity Tracking

No constitution violations require justification. The plan deliberately avoids a new interface, build stage, dependency, or persistent cleanup state.
