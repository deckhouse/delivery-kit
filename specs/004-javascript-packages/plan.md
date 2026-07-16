---
status: draft
feature: javascript-packages
created: 2026-07-15
source: spec
---

# Implementation Plan: JavaScript Package Ecosystems

**Branch**: `004-javascript-packages` | **Date**: 2026-07-15 | **Spec**: [spec.md](spec.md)

## Summary

Add three JavaScript package manager types (`javascript-npm`, `javascript-yarn`, `javascript-pnpm`) to werf's `packages` config directive. Each type registers a `PackageEcosystem` entry in the existing `ecosystems` map with its own install command, default spec/lock files, and Syft cataloger mapping. No new infrastructure is needed — the existing `FileBasedSpec` + ecosystem registry pattern handles everything.

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

## Constitution Check

*GATE: Must pass before Phase 0 research. Re-check after Phase 1 design.*

| Principle | Check | Notes |
|-----------|-------|-------|
| **I. Simplicity Over Abstraction** | ✅ PASS | Adding JavaScript types is purely additive: 3 new constants + 3 map entries. No new structs, interfaces, or generics. The existing `FileBasedSpec` + ecosystem registry pattern from Python/Rust is reused as-is. This follows the simplest possible approach. |
| **II. Go Idiomatic Code** | ✅ PASS | Follows existing patterns: `fmt.Sprintf` for command generation, `context.Context` in public functions (none new needed), guard clauses in validation. |
| **III. Minimal Public Surface** | ✅ PASS | Constants are package-private in `config` package. The `Ecosystems()` function is already public and reused. No new public API surface. |
| **IV. Test-Before-Merge** | ✅ PASS | Tests follow Ginkgo + Gomega pattern, co-located with source. Unit tests for config parsing, SBOM catalogers, command generation. |
| **V. Conventional Commits** | ✅ PASS | Commits in `feat(sbom):` or `feat(config):` scope. |

**Decision**: ✅ All gates pass. Proceed to Phase 0 research.

## Project Structure

### Documentation (this feature)

```text
specs/004-javascript-packages/
├── spec.md              # Feature specification
├── plan.md              # This file (implementation plan)
├── research.md          # Phase 0 research findings
├── data-model.md        # Phase 1 data model
├── quickstart.md        # Phase 1 validation guide
├── contracts/           # Phase 1 interface contracts
│   ├── config-schema.md       # YAML config schema for JavaScript types
│   └── ecosystem-registry.md  # Ecosystem registry contract
└── checklists/
    └── requirements.md  # Specification quality checklist
```

### Source Code (repository root)

```text
pkg/config/
  packages_directive.go              — 3 new constants + 3 new ecosystem entries (< 20 lines added)
  packages_directive_javascript_test.go — New: unmarshal, defaults, error cases (~120 lines)

pkg/sbom/managedinput/
  managedinput_test.go               — Extended: ToCatalogers and FilterBOMBySourcePaths tests (~150 lines added)

pkg/build/stage/
  packages_test.go                   — Extended: GeneratePackagesCommands tests (~30 lines added)

test/e2e/sbom/
  npm_test.go                        — New: e2e test for npm (~42 lines)
  yarn_test.go                       — New: e2e test for yarn (~42 lines)
  pnpm_test.go                       — New: e2e test for pnpm (~42 lines)
  _fixtures/inject/npm_simple/       — New: fixture (package.json + package-lock.json)
  _fixtures/inject/yarn_simple/      — New: fixture (package.json + yarn.lock)
  _fixtures/inject/pnpm_simple/      — New: fixture (package.json + pnpm-lock.yaml)

docs/_data/
  werf_yaml.yml                      — Updated type descriptions (add javascript-npm, javascript-yarn, javascript-pnpm)

docs/pages_en/usage/build/stapel/instructions.md  — Updated: added JavaScript sections
docs/pages_ru/usage/build/stapel/instructions.md  — Updated: added JavaScript sections
```

## Complexity Assessment

- **File count**: ~15 files changed (1 source, 3 unit test, 3 e2e + fixtures, 3 docs)
- **Source LOC added**: ~20 (net) — three constants + three ecosystem entries
- **Test LOC added**: ~300 (unit) + ~126 (e2e) + fixture data
- **Dependency changes**: None — all new types use existing packages and tools
- **Risk**: Very low — the feature is purely additive; no existing behavior is modified; the registry pattern already exists and is proven by Go-mod, Python, and Rust types

## Design Decisions

1. **Three separate types over one `javascript` type with a manager sub-field** — Following the established pattern from Python (`python-uv`, `python-pip`, `python-poetry`), each JavaScript package manager gets its own type. This keeps the YAML flat and unambiguous, and avoids the need for ecosystem-specific validation logic.

2. **`npm ci` over `npm install`** — `npm ci` is the correct command for CI/CD environments: it is faster, fails if `package-lock.json` is missing or out of sync, and produces deterministic installs.

3. **`--frozen-lockfile` for yarn and pnpm** — Both managers support this flag, which ensures lock file consistency and fails the build if the lock file is out of date.

4. **Shared cataloger for all JavaScript types** — Syft uses `javascript-lock-cataloger` for all three lock file formats and `javascript-package-cataloger` for `package.json`. This is already handled by the cataloger name mapping in the ecosystem registry — no Syft configuration changes needed.

5. **Naming convention** — `javascript-<manager>` (not `js-<manager>` or `<manager>-js`) follows the `<language>-<manager>` pattern established by `python-uv`, `python-pip`, `python-poetry`, and `rust-cargo`.

## Complexity Tracking

No constitution violations. All gates pass.