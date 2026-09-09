# Implementation Plan: Alternative Language Package Managers

**Branch**: `022-alternative-language-package-managers` | **Date**: 2026-09-07 | **Spec**: [spec.md](spec.md)

**Input**: Feature specification from `/specs/022-alternative-language-package-managers/spec.md`

## Summary

Add isolated bootstrap support for Yarn, pnpm, uv, and Poetry in file-based `packages` directives. Each directive receives a required `version` accepted by `github.com/Masterminds/semver/v3`, and the selected alternative manager must be absent from the builder image. The generated command uses one readable `if ... then ... else ... fi` block: it rejects a pre-installed alternative manager, otherwise installs the manager into a directive-local temporary scope through npm or pip, performs the existing frozen dependency installation through that scope, and removes only the temporary scope after success. Environment variables are applied to the individual external commands that need them rather than to the complete multi-line shell block. Compatibility between manager versions and the commands in `packages` is explicitly deferred to the Kaiten follow-up task. The implementation extends the existing `pkg/config` ecosystem registry and package-stage command generation, preserving current primary-manager and SBOM behavior.

## Technical Context

**Language/Version**: Go 1.24.10

**Primary Dependencies**: Existing werf Go dependencies, including the already-present `github.com/Masterminds/semver/v3` and `github.com/google/uuid` dependencies. Package managers remain external tools invoked inside the builder image through existing shell-stage execution; no new external dependency is planned.

**Storage**: Existing Buildah/container backend stage filesystem and package-stage cache. No new persistent storage.

**Testing**: Ginkgo + Gomega unit tests alongside `pkg/config` and `pkg/build/stage`; existing SBOM e2e suites for Yarn, pnpm, uv, and Poetry.

**Target Platform**: Linux container builds; Docker-backed e2e scenarios and prepared Buildah-capable environment.

**Project Type**: Go CLI tool with YAML configuration, container image build stages, and SBOM generation.

**Performance Goals**: Preserve package-stage caching; manager version and lifecycle commands must participate in the existing package-stage checksum. Do not add an extra build stage or independent lock scan.

**Constraints**: Reuse the existing `Masterminds/semver/v3` and `github.com/google/uuid` dependencies; accept every version that `semver` considers valid; no change to primary package types; POSIX shell commands available through the existing Stapel builder; change into the directive `workdir` before bootstrap so project-local configuration is used by bootstrap commands; preserve frozen lock semantics and managed-input SBOM source paths; require the selected alternative manager to be absent from the builder image; use a unique directive-local npm prefix or Python virtual environment rather than a project tree or shared global environment; generate a unique scope identifier in Go with `github.com/google/uuid`, pass it to the command template, and create the scope with `stapel.MkdirBinPath()`; remove the general `prefixCommand(lifecycle, env)` call from `InstallCmd` only, and pass the generated env prefix directly before the external commands that need it; do not apply it to `cd` or `rm`; the current Stapel embedded toolchain does not provide `grep` or `mktemp`, so do not introduce accessors or generated commands for them; version-output verification, including any `grep`-based comparison, is out of scope for this feature and tracked separately; use the existing Stapel embedded path for `rm` and other utilities only where that path is available; remove the redundant inner `set -e` because the generated script already runs with fail-fast semantics; cleanup only on successful dependency installation; manager-version compatibility with the current `packages` command syntax is out of scope and tracked separately in Kaiten.

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

pkg/build/stage/testdata/
└── packages_commands/
    ├── javascript-yarn.golden
    ├── javascript-pnpm.golden
    ├── python-uv.golden
    └── python-poetry.golden

pkg/stapel/
└── stapel.go                   # existing embedded lifecycle utility paths only; no grep/mktemp accessors

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

**Structure Decision**: Reuse the existing monolith CLI boundaries and `PackageEcosystem` registry. Determine alternative-manager behavior with a switch over the four supported directive types; do not add an `isAlternativeManager` field to the registry. Introduce one internal command-wrapper type/factory that centralizes the repeated `cd` and environment-prefix logic and returns an install-command function. Remove the general `prefixCommand(lifecycle, env)` call only from `InstallCmd`; pass the generated env prefix as an additional positional template argument directly before the external bootstrap/install/manager commands that need it. Do not apply that prefix to shell builtins or unrelated commands. The current Stapel embedded toolchain does not support `grep` or `mktemp`: generate a collision-safe unique scope with available shell/embedded primitives instead of `mktemp`, compare or parse versions with shell builtins or another already-available mechanism instead of `grep`, and use `stapel.RmBinPath()` for cleanup. Do not add `MktempBinPath`/`GrepBinPath` accessors for unavailable tools. `command -v` remains a shell builtin. Do not add an inner `set -e`; the enclosing generated script already runs with `-e`. When configured for an alternative manager, the wrapper emits one readable lifecycle command sequence: it rejects a pre-installed executable, creates an ephemeral scope, installs and verifies the manager, runs the dependency command, and removes only that scope after success. Do not add a package-manager service, interface hierarchy, persistent cleanup state, or new build stage.

## Phase 0: Research Summary

Research is recorded in [research.md](research.md). Key resolved decisions:

1. YAML field name is `version`, stored as a string and validated with the existing `github.com/Masterminds/semver/v3`; every version accepted by that library is accepted by this validation layer.
2. Compatibility of accepted manager versions with the current generated `packages` commands is not resolved in this feature; it is tracked in Kaiten card [69824840](https://flant.kaiten.ru/69824840).
3. The switch helper selects the four alternative manager types without storing a classification field in `PackageEcosystem`.
4. The command-wrapper factory emits the complete readable conditional, changes into the directive workdir before bootstrap, rejects a pre-installed alternative manager, creates the ecosystem-specific ephemeral scope using a Go-generated `github.com/google/uuid` identifier and `stapel.MkdirBinPath()`, invokes the isolated executable with env variables applied per external command, and composes scope removal through the available Stapel cleanup path without adding a nested `set -e`. Post-bootstrap version-output verification is out of scope.
5. Existing lock flags, package-stage checksum, managed-input catalogers, and SBOM source paths remain authoritative. Scope creation uses a Go-generated UUID and the embedded Stapel `mkdir`; lifecycle cleanup uses the available embedded Stapel `rm`. The generated commands must not assume that the base image or Stapel embedded toolchain provides `mktemp` or `grep`; post-bootstrap version-output verification is deferred.
6. Existing four alternative-manager e2e scenarios are the dedicated acceptance coverage; their fixtures need valid SemVer versions and must omit pre-installed alternatives, with negative coverage for the rejection branch where feasible.
7. Version-validation tests use a Ginkgo/Gomega `DescribeTable` covering required, invalid, unsupported-type, and valid SemVer cases, including prerelease/build metadata. Focused command tests cover UUID scope propagation, embedded `mkdir`/`rm` paths, env propagation, failure ordering, and lifecycle diagnostics; post-bootstrap version-output verification is not tested in this feature.
8. Documentation updates cover both EN and RU package-directive pages: the `version` field and its requiredness, Python `python3`/`venv` prerequisites, and migration from images with pre-installed managers. Supported version ranges are excluded because they are part of the Kaiten follow-up. The `AGENTS.md` note about remote taskfiles is intentionally removed as part of this change.

## Phase 1: Design Summary

- Data model and state transitions are in [data-model.md](data-model.md).
- YAML/build/SBOM contracts are in [contracts/configuration.md](contracts/configuration.md) and [contracts/build-and-sbom.md](contracts/build-and-sbom.md).
- Runnable validation scenarios are in [quickstart.md](quickstart.md).

### Implementation sequencing

1. Extend raw and typed package directive models with `Version`; apply defaults without changing existing spec/lock behavior.
2. Use the existing `github.com/Masterminds/semver/v3` dependency for version validation and accept its complete valid syntax, including prerelease/build metadata; generate each directive-local scope identifier in Go with the existing `github.com/google/uuid` dependency; keep manager-command compatibility and post-bootstrap version-output verification out of this validation change.
3. Add an internal switch helper that returns true only for `javascript-yarn`, `javascript-pnpm`, `python-uv`, and `python-poetry`; use it for version validation and alternative-manager command selection.
4. Introduce the internal command-wrapper type/factory that centralizes `cd` and environment-prefix generation and returns the `InstallCmd` function shape used by `PackageEcosystem`.
5. Configure the wrapper for alternative managers so each ecosystem emits one complete `if ... then ... else ... fi` block: the `then` branch rejects a pre-installed executable, while the `else` branch changes into the directive workdir before bootstrap and keeps Go-generated UUID scope creation, version bootstrap, frozen dependency installation, and embedded-toolchain cleanup on separate readable lines under the enclosing fail-fast shell execution. Apply the env prefix as an additional positional template argument immediately before the external commands that need it; leave `cd` and `rm` unprefixed, use `stapel.MkdirBinPath()` and `stapel.RmBinPath()` for scope lifecycle, and do not emit unavailable `mktemp` or `grep` commands. Keep the lifecycle readable and ensure a pre-installed manager cannot be silently reused; do not emit a redundant inner `set -e` or a post-bootstrap version-output check.
6. Refactor duplicated `InstallCmd` closures in `pkg/config/packages_directive.go` to use the wrapper while preserving primary and unrelated ecosystem behavior. Remove the general `prefixCommand(lifecycle, env)` call only at the selected `InstallCmd` return site, avoid persistent `PATH` changes, and ensure errors remain operation-specific and command content affects package-stage caching.
7. Add focused Ginkgo/Gomega tests for the switch helper, complete generated wrapper snippets, workdir selection before bootstrap, env propagation to a stub external manager, UUID scope propagation, embedded `mkdir`/`rm` paths, absence of `mktemp`/`grep` and a redundant inner `set -e`, parsing, required/invalid/unsupported-type/valid-SemVer validation cases in a `DescribeTable`, pre-installed-manager rejection, failure ordering, scope cleanup, primary types, and multiple directives; compare each full snippet against an independent expected value rather than generating the expectation with the function under test. Post-bootstrap version-output verification is out of scope.
8. Add independent golden expectations under `pkg/build/stage/testdata/packages_commands/` for the full generated Yarn, pnpm, uv, and Poetry command snippets. The tests must read and compare these files directly, must not derive expectations via `GeneratePackagesCommands`, and must not provide an automatic golden-update mode. Keep separate behavioral tests for validation, failure handling, env propagation, scope lifecycle, and cleanup because golden files verify generated structure rather than executing the shell.
9. Update the four existing SBOM e2e fixtures/tests with valid SemVer versions, pre-installed-manager rejection coverage where representable, temporary-scope cleanup assertions, and existing dependency SBOM assertions.
10. Update both EN and RU package-directive reference documentation with the required `version` field, Python `python3`/`venv` prerequisites, and migration guidance for images with pre-installed managers. Do not document supported version ranges in this feature; they are tracked in Kaiten card 69824840. Preserve the intentional `AGENTS.md` remote-taskfile-note removal and do not modify generated release files.

## Constitution Check (Post-Design)

- **Simplicity — PASS:** one small internal command wrapper removes duplicated shell composition without introducing a service or interface hierarchy; isolation and the pre-installed-manager rejection remain implementation details of the generated command function.
- **Idiomatic Go — PASS:** typed field and internal helpers follow current config/command patterns; errors include operation context.
- **Minimal surface — PASS:** only the per-directive `version` configuration field is user-visible; the switch and wrapper remain internal.
- **Testing — PASS:** unit and e2e coverage directly maps to every manager and failure lifecycle; generated command tests use independent golden expectations and do not compare the function under test with itself.
- **Dependencies and boundaries — PASS:** no new dependency is added; the already-present SemVer library is reused, and no cross-layer inversion is introduced.
- **Documentation and scope — PASS:** EN/RU package-directive documentation covers the approved prerequisites and migration guidance; version-range compatibility remains explicitly deferred to Kaiten card 69824840, post-bootstrap version-output verification is separately out of scope, and the intentional `AGENTS.md` removal is recorded rather than treated as an accidental drive-by change.
- **Quality gates — PASS:** implementation validation follows the repository-required `task` commands and scoped e2e commands in `quickstart.md`.

## Complexity Tracking

No constitution violations require justification. The plan deliberately avoids a new interface, build stage, dependency, shared global mutation, or persistent cleanup state.
