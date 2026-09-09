# Implementation Plan: Alternative Language Package Managers

**Branch**: `022-alternative-language-package-managers` | **Date**: 2026-09-07 | **Spec**: [spec.md](spec.md)

**Input**: Feature specification from `/specs/022-alternative-language-package-managers/spec.md`

## Summary

Add isolated bootstrap support for Yarn, pnpm, uv, and Poetry in file-based `packages` directives. Each directive receives a required `version` accepted by `github.com/Masterminds/semver/v3`, and the selected alternative manager must be absent from the builder image. The generated command uses one readable `if ... then ... else ... fi` block: it rejects a pre-installed alternative manager, otherwise installs the manager into a directive-local temporary scope through npm or pip, performs the existing frozen dependency installation through that scope, and removes only the temporary scope after success. Environment variables are applied to the individual external commands that need them rather than to the complete multi-line shell block. Compatibility between manager versions and the commands in `packages` is explicitly deferred to the Kaiten follow-up task. The implementation extends the existing `pkg/config` ecosystem registry and package-stage command generation, preserving current primary-manager and SBOM behavior.

## Technical Context

**Language/Version**: Go 1.24.10

**Primary Dependencies**: Existing werf Go dependencies, including the already-present `github.com/Masterminds/semver/v3` dependency. Package managers remain external tools invoked inside the builder image through existing shell-stage execution; no new external dependency is planned.

**Storage**: Existing Buildah/container backend stage filesystem and package-stage cache. No new persistent storage.

**Testing**: Ginkgo + Gomega unit tests alongside `pkg/config` and `pkg/build/stage`; existing SBOM e2e suites for Yarn, pnpm, uv, and Poetry.

**Target Platform**: Linux container builds; Docker-backed e2e scenarios and prepared Buildah-capable environment.

**Project Type**: Go CLI tool with YAML configuration, container image build stages, and SBOM generation.

**Performance Goals**: Preserve package-stage caching; manager version and lifecycle commands must participate in the existing package-stage checksum. Do not add an extra build stage or independent lock scan.

**Constraints**: No new dependency; use the existing `Masterminds/semver/v3` dependency and accept every version that it considers valid; no change to primary package types; POSIX shell commands available through the existing Stapel builder; preserve frozen lock semantics and managed-input SBOM source paths; require the selected alternative manager to be absent from the builder image; use a unique directive-local npm prefix or Python virtual environment rather than a project tree or shared global environment; remove the general `prefixCommand(lifecycle, env)` call from `InstallCmd` only, and pass the generated env prefix directly before the external commands that need it; do not apply it to `mktemp`, `cd`, `grep`, or `rm`; use Stapel embedded-toolchain paths for lifecycle utilities rather than assuming coreutils in the base image; remove the redundant inner `set -e` because the generated script already runs with fail-fast semantics; cleanup only on successful dependency installation; manager-version compatibility with the current `packages` command syntax is out of scope and tracked separately in Kaiten.

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

pkg/stapel/
└── stapel.go                   # embedded paths for lifecycle utilities if accessors are needed

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
├── pages_en/usage/build/stapel/instructions.md
└── pages_ru/usage/build/stapel/instructions.md # document version, prerequisites, and migration guidance

AGENTS.md # retain the intentional removal of the remote-taskfile note
```

**Structure Decision**: Reuse the existing monolith CLI boundaries and `PackageEcosystem` registry. Determine alternative-manager behavior with a switch over the four supported directive types; do not add an `isAlternativeManager` field to the registry. Introduce one internal command-wrapper type/factory that centralizes the repeated `cd` and environment-prefix logic and returns an install-command function. Remove the general `prefixCommand(lifecycle, env)` call only from `InstallCmd`; pass the generated env prefix as an additional positional template argument directly before the external bootstrap/install/manager commands that need it. Do not apply that prefix to shell builtins or unrelated commands. Use Stapel embedded-toolchain paths for `mktemp`, `grep`, and `rm`; `command -v` remains a shell builtin. Since the current Stapel package exposes `RmBinPath` but not dedicated `MktempBinPath`/`GrepBinPath` accessors, add the narrowest accessors or equivalent path construction consistent with its existing API rather than using bare base-image binaries. Do not add an inner `set -e`; the enclosing generated script already runs with `-e`. When configured for an alternative manager, the wrapper emits one readable lifecycle command sequence: it rejects a pre-installed executable, creates an ephemeral scope, installs and verifies the manager, runs the dependency command, and removes only that scope after success. Do not add a package-manager service, interface hierarchy, persistent cleanup state, or new build stage.

## Phase 0: Research Summary

Research is recorded in [research.md](research.md). Key resolved decisions:

1. YAML field name is `version`, stored as a string and validated with the existing `github.com/Masterminds/semver/v3`; every version accepted by that library is accepted by this validation layer.
2. Compatibility of accepted manager versions with the current generated `packages` commands is not resolved in this feature; it is tracked in Kaiten card [69824840](https://flant.kaiten.ru/69824840).
3. The switch helper selects the four alternative manager types without storing a classification field in `PackageEcosystem`.
4. The command-wrapper factory emits the complete readable conditional, rejects a pre-installed alternative manager, creates the ecosystem-specific ephemeral scope with Stapel embedded-toolchain utilities, invokes the isolated executable with env variables applied per external command, and composes scope removal into the generated install function without adding a nested `set -e`.
5. Existing lock flags, package-stage checksum, managed-input catalogers, and SBOM source paths remain authoritative. Lifecycle utilities use the embedded Stapel toolchain so the generated commands do not require base-image coreutils.
6. Existing four alternative-manager e2e scenarios are the dedicated acceptance coverage; their fixtures need valid SemVer versions and must omit pre-installed alternatives, with negative coverage for the rejection branch where feasible.
7. Version-validation tests use a Ginkgo/Gomega `DescribeTable` covering required, invalid, unsupported-type, and valid SemVer cases, including prerelease/build metadata. Diagnostics for lifecycle failures and exact version verification are covered by focused command tests.
8. Documentation updates cover both EN and RU package-directive pages: the `version` field and its requiredness, Python `python3`/`venv` prerequisites, and migration from images with pre-installed managers. Supported version ranges are excluded because they are part of the Kaiten follow-up. The `AGENTS.md` note about remote taskfiles is intentionally removed as part of this change.

## Phase 1: Design Summary

- Data model and state transitions are in [data-model.md](data-model.md).
- YAML/build/SBOM contracts are in [contracts/configuration.md](contracts/configuration.md) and [contracts/build-and-sbom.md](contracts/build-and-sbom.md).
- Runnable validation scenarios are in [quickstart.md](quickstart.md).

### Implementation sequencing

1. Extend raw and typed package directive models with `Version`; apply defaults without changing existing spec/lock behavior.
2. Use the existing `github.com/Masterminds/semver/v3` dependency for version validation and accept its complete valid syntax, including prerelease/build metadata; keep manager-command compatibility out of this validation change.
3. Add an internal switch helper that returns true only for `javascript-yarn`, `javascript-pnpm`, `python-uv`, and `python-poetry`; use it for version validation and alternative-manager command selection.
4. Introduce the internal command-wrapper type/factory that centralizes `cd` and environment-prefix generation and returns the `InstallCmd` function shape used by `PackageEcosystem`.
5. Configure the wrapper for alternative managers so each ecosystem emits one complete `if ... then ... else ... fi` block: the `then` branch rejects a pre-installed executable, while the `else` branch keeps scope creation, version bootstrap and verification, frozen dependency installation, and embedded-toolchain cleanup on separate readable lines under the enclosing fail-fast shell execution. Apply the env prefix as an additional positional template argument immediately before the external commands that need it; leave `mktemp`, `cd`, `grep`, and `rm` unprefixed, while rendering the utility commands through Stapel embedded paths. Keep the lifecycle readable and ensure a pre-installed manager cannot be silently reused; do not emit a redundant inner `set -e`.
6. Refactor duplicated `InstallCmd` closures in `pkg/config/packages_directive.go` to use the wrapper while preserving primary and unrelated ecosystem behavior. Remove the general `prefixCommand(lifecycle, env)` call only at the selected `InstallCmd` return site, avoid persistent `PATH` changes, and ensure errors remain operation-specific and command content affects package-stage caching.
7. Add focused Ginkgo/Gomega tests for the switch helper, complete generated wrapper snippets, env propagation to a stub external manager, embedded-toolchain utility paths, absence of a redundant inner `set -e`, parsing, required/invalid/unsupported-type/valid-SemVer validation cases in a `DescribeTable`, pre-installed-manager rejection, exact version diagnostics, failure ordering, scope cleanup, primary types, and multiple directives; compare each full snippet rather than isolated command lines.
8. Update the four existing SBOM e2e fixtures/tests with valid SemVer versions, pre-installed-manager rejection coverage where representable, temporary-scope cleanup assertions, and existing dependency SBOM assertions.
9. Update both EN and RU package-directive reference documentation with the required `version` field, Python `python3`/`venv` prerequisites, and migration guidance for images with pre-installed managers. Do not document supported version ranges in this feature; they are tracked in Kaiten card 69824840. Preserve the intentional `AGENTS.md` remote-taskfile-note removal and do not modify generated release files.

## Constitution Check (Post-Design)

- **Simplicity — PASS:** one small internal command wrapper removes duplicated shell composition without introducing a service or interface hierarchy; isolation and the pre-installed-manager rejection remain implementation details of the generated command function.
- **Idiomatic Go — PASS:** typed field and internal helpers follow current config/command patterns; errors include operation context.
- **Minimal surface — PASS:** only the per-directive `version` configuration field is user-visible; the switch and wrapper remain internal.
- **Testing — PASS:** unit and e2e coverage directly maps to every manager and failure lifecycle.
- **Dependencies and boundaries — PASS:** no new dependency is added; the already-present SemVer library is reused, and no cross-layer inversion is introduced.
- **Documentation and scope — PASS:** EN/RU package-directive documentation covers the approved prerequisites and migration guidance; version-range compatibility remains explicitly deferred to Kaiten card 69824840, and the intentional `AGENTS.md` removal is recorded rather than treated as an accidental drive-by change.
- **Quality gates — PASS:** implementation validation follows the repository-required `task` commands and scoped e2e commands in `quickstart.md`.

## Complexity Tracking

No constitution violations require justification. The plan deliberately avoids a new interface, build stage, dependency, shared global mutation, or persistent cleanup state.
