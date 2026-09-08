# Implementation Plan: Alternative Language Package Managers

**Branch**: `022-alternative-language-package-managers` | **Date**: 2026-09-07 | **Spec**: [spec.md](spec.md)

**Input**: Feature specification from `/specs/022-alternative-language-package-managers/spec.md`

## Summary

Add isolated bootstrap support for Yarn, pnpm, uv, and Poetry in file-based `packages` directives. Each directive receives a required exact `version`, and the selected alternative manager must be absent from the builder image. The generated command uses one readable `if ... then ... else ... fi` block: it rejects a pre-installed alternative manager, otherwise installs the manager into a directive-local temporary scope through npm or pip, performs the existing frozen dependency installation through that scope, and removes only the temporary scope after success. The implementation extends the existing `pkg/config` ecosystem registry and package-stage command generation, preserving current primary-manager and SBOM behavior.

## Technical Context

**Language/Version**: Go 1.24.10

**Primary Dependencies**: Existing werf Go dependencies; no new external dependencies planned. Package managers remain external tools invoked inside the builder image through existing shell-stage execution.

**Storage**: Existing Buildah/container backend stage filesystem and package-stage cache. No new persistent storage.

**Testing**: Ginkgo + Gomega unit tests alongside `pkg/config` and `pkg/build/stage`; existing SBOM e2e suites for Yarn, pnpm, uv, and Poetry.

**Target Platform**: Linux container builds; Docker-backed e2e scenarios and prepared Buildah-capable environment.

**Project Type**: Go CLI tool with YAML configuration, container image build stages, and SBOM generation.

**Performance Goals**: Preserve package-stage caching; manager version and lifecycle commands must participate in the existing package-stage checksum. Do not add an extra build stage or independent lock scan.

**Constraints**: No new dependency; no change to primary package types; POSIX shell commands available through the existing Stapel builder; preserve frozen lock semantics and managed-input SBOM source paths; require the selected alternative manager to be absent from the builder image; use a unique directive-local npm prefix or Python virtual environment rather than a project tree or shared global environment; cleanup only on successful dependency installation.

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

**Structure Decision**: Reuse the existing monolith CLI boundaries and `PackageEcosystem` registry. Determine alternative-manager behavior with a switch over the four supported directive types; do not add an `isAlternativeManager` field to the registry. Introduce one internal command-wrapper type/factory that centralizes the repeated `cd` and environment-prefix logic and returns an install-command function. When configured for an alternative manager, the wrapper emits one readable lifecycle command sequence: it rejects a pre-installed executable, creates an ephemeral scope, installs and verifies the manager, runs the dependency command, and removes only that scope after success. Do not add a package-manager service, interface hierarchy, persistent cleanup state, or new build stage.

## Phase 0: Research Summary

Research is recorded in [research.md](research.md). Key resolved decisions:

1. YAML field name is `version`, stored as a string and validated as exact `X.Y.Z` for alternative types.
2. The switch helper selects the four alternative manager types without storing a classification field in `PackageEcosystem`.
3. The command-wrapper factory emits the complete readable conditional, rejects a pre-installed alternative manager, creates the ecosystem-specific ephemeral scope, invokes the isolated executable, and composes scope removal into the generated install function.
4. Existing lock flags, package-stage checksum, managed-input catalogers, and SBOM source paths remain authoritative.
5. Existing four alternative-manager e2e scenarios are the dedicated acceptance coverage; their fixtures need exact versions and must omit pre-installed alternatives, with negative coverage for the rejection branch where feasible.

## Phase 1: Design Summary

- Data model and state transitions are in [data-model.md](data-model.md).
- YAML/build/SBOM contracts are in [contracts/configuration.md](contracts/configuration.md) and [contracts/build-and-sbom.md](contracts/build-and-sbom.md).
- Runnable validation scenarios are in [quickstart.md](quickstart.md).

### Implementation sequencing

1. Extend raw and typed package directive models with `Version`; apply defaults without changing existing spec/lock behavior.
2. Add an internal switch helper that returns true only for `javascript-yarn`, `javascript-pnpm`, `python-uv`, and `python-poetry`; use it for version validation and alternative-manager command selection.
3. Introduce the internal command-wrapper type/factory that centralizes `cd` and environment-prefix generation and returns the `InstallCmd` function shape used by `PackageEcosystem`.
4. Configure the wrapper for alternative managers so each ecosystem emits one complete `if ... then ... else ... fi` block: the `then` branch rejects a pre-installed executable, while the `else` branch keeps scope creation, exact-version bootstrap and verification, frozen dependency installation, and `rm -rf "$scope"` cleanup on separate readable lines under fail-fast shell execution. Keep the lifecycle readable and ensure a pre-installed manager cannot be silently reused.
5. Refactor duplicated `InstallCmd` closures in `pkg/config/packages_directive.go` to use the wrapper while preserving primary and unrelated ecosystem behavior. Keep the complete alternative-manager lifecycle inside one readable `if ... then ... else ... fi` block per ecosystem, avoid persistent `PATH` changes, and ensure errors remain operation-specific and command content affects package-stage caching.
6. Add focused Ginkgo/Gomega tests for the switch helper, complete generated wrapper snippets, parsing, invalid versions, pre-installed-manager rejection, failure ordering, scope cleanup, primary types, and multiple directives; compare each full snippet rather than isolated command lines.
7. Update the four existing SBOM e2e fixtures/tests with exact versions, pre-installed-manager rejection coverage where representable, temporary-scope cleanup assertions, and existing dependency SBOM assertions.
8. Update package-directive reference documentation for the new required field and examples in supported languages, without modifying generated release files.

## Constitution Check (Post-Design)

- **Simplicity — PASS:** one small internal command wrapper removes duplicated shell composition without introducing a service or interface hierarchy; isolation and the pre-installed-manager rejection remain implementation details of the generated command function.
- **Idiomatic Go — PASS:** typed field and internal helpers follow current config/command patterns; errors include operation context.
- **Minimal surface — PASS:** only the per-directive `version` configuration field is user-visible; the switch and wrapper remain internal.
- **Testing — PASS:** unit and e2e coverage directly maps to every manager and failure lifecycle.
- **Dependencies and boundaries — PASS:** no new dependency and no cross-layer inversion.
- **Quality gates — PASS:** implementation validation follows the repository-required `task` commands and scoped e2e commands in `quickstart.md`.

## Complexity Tracking

No constitution violations require justification. The plan deliberately avoids a new interface, build stage, dependency, shared global mutation, or persistent cleanup state.
