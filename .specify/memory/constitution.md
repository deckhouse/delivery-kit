<!--
  Sync Impact Report
  Version: 1.3.0 → 1.4.0 (MINOR — pm.lock generation now goes through `task pm:lock`)
  Modified principles: (none)
  Modified sections:
    - Build & Quality Gates: pm.lock generation entry now mandates `task pm:lock`
      (dockerized pm from the digest-pinned container-factory image) instead of
      a bare `pm lock` invocation
  Removed sections: (none)
  Templates requiring updates:
    - ✅ delivery-kit/AGENTS.md (Commands section)
  Follow-up TODOs: (none)
-->
# Delivery Kit Constitution

## Core Principles

### I. Simplicity Over Abstraction

Prefer stupid and simple over abstract and extendable. Prefer a bit of duplication over complex abstractions. Minimize interfaces, generics, and embedding. Prefer functions over methods, public fields over getters/setters, and data types over types with behavior.

### II. Go Idiomatic Code

Follow Effective Go and Go Code Review Comments. All public functions MUST accept `context.Context` as the first parameter. Errors MUST be wrapped with context using `fmt.Errorf("doing something: %w", err)`. Use guard clauses and early returns. Never use `this`/`self` as receiver names, never use named returns, never use dot imports.

### III. Minimal Public Surface

Keep everything private/internal as much as possible. Validate early, validate a lot. Keep APIs stupid and minimal. When in doubt, don't add comments — only document non-obvious public APIs or genuinely non-obvious logic.

### IV. Test-Before-Merge

Tests are co-located with source files (`*_test.go`).
All tests MUST use Ginkgo + Gomega stack — no `testing`/`testify`
(`assert`/`require`). After EVERY code change, ALL relevant tests
(unit and e2e) MUST be re-executed — never rely on earlier pass
results.

**`--` separator rule**: NEVER place `KEY=VALUE` variable assignments
after the `--` separator. The `--` separator forwards arguments to the
ginkgo runner (`CLI_ARGS`), and invalid positional arguments cause ginkgo
to compile ALL packages instead of only the targeted ones, leading to
excessive memory usage. Use `--` ONLY for passing flags directly to
ginkgo (e.g., `-- -focus=MyTest -v`).

**Unit tests**:
- `task test:unit`
- Scoped: `task test:unit paths="./pkg/sbom/..."`
- With ginkgo flags: `task test:unit paths="./pkg/sbom/..." -- -focus=MyTest`

**E2E tests** (environment is pre-configured — see Environment Configuration section below):
- `task test:e2e` (defaults to `./test/e2e`)
- Scoped: `task test:e2e paths="./test/e2e/sbom/..." labelFilter="sbom"`
- Complex filter: `task test:e2e paths="./test/e2e/sbom/..." labelFilter="sbom && (packages || lifecycle || gost)"`

Mocks MUST be generated with `task mock:generate` — never write mocks by hand.

### V. Conventional Commits

All commits MUST follow the Conventional Commits format: `type(scope): description`. Branch names follow the same pattern: `feat/*`, `fix/*`, `chore/*`, `deps/*`. PRs are titled and described per werf conventions.

## Code Boundaries

| Layer | Path | Purpose |
|-------|------|---------|
| **CLI commands** | `cmd/werf/` | Cobra command tree — thin wiring layer, no business logic |
| **Libraries** | `pkg/...` | All business logic, organized by domain (build, deploy, sbom, cleanup, etc.) |
| **E2E tests** | `test/e2e/` | Ginkgo end-to-end test suites |
| **Legacy tests** | `test/legacy_e2e/` | Legacy integration tests |
| **Shared test helpers** | `test/pkg/` | Reusable test utilities and mocks |

## Dependency Rules

- Internal packages in `pkg/` may import other `pkg/` subpackages freely
- `cmd/werf/` may import any `pkg/` subpackage but NOT other `cmd/` packages
- External dependencies are managed via `go.mod`. Adding new dependencies MUST be flagged for review.
- No dependency on `cmd/` packages from `pkg/`
- All 3rd-party forks are documented in `go.mod` `replace` directives with reasons

## Build & Quality Gates

- **Build**: `task build` (NOT raw `go build`)
- **Unit tests**: `task test:unit` (NOT raw `go test`)
  - Scoped: `task test:unit paths="./pkg/sbom/..."`
  - With ginkgo flags: `task test:unit paths="./pkg/sbom/..." -- -focus=MyTest`
  - NEVER place `KEY=VALUE` after `--` separator (see principle IV).
- **E2E tests**: `task test:e2e` (NOT raw `go test`)
  - Scoped: `task test:e2e paths="./test/e2e/sbom/..." labelFilter="sbom"`
  - Complex filter: `task test:e2e paths="./test/e2e/sbom/..." labelFilter="sbom && (packages || lifecycle || gost)"`
  - NEVER place `KEY=VALUE` after `--` separator — it compiles ALL tests.
  - Use `--` ONLY for ginkgo flags (e.g., `-- -focus=MyTest -v`).
- **pm.lock generation**: `task pm:lock dir=<project-dir>` (NOT hand-written and NOT bare `pm lock`; `pm.lock` is a deterministic machine-generated artifact committed alongside `pm.yaml`). The task runs pm inside the digest-pinned `registry.deckhouse.io/container-factory` image, so it needs only Docker. For a non-default manifest/lock file name, pass `from=<spec>` and `lock=<lock>` — the manifest path is recorded in the lock metadata, so the file name matters. NEVER invent or edit `pm.lock` contents manually.
- **Formatting**: `task format` (NOT raw `go fmt`)
- **Mock generation**: `task mock:generate` (no manual mocks; validate with `task mock:check`)
- **Documentation**: `task doc:gen` after changing CLI help text

## Environment Configuration

The e2e and integration test environment has been pre-configured.
`task test:setup:environment` has already been executed and the following
infrastructure is available:

- **Docker**: Docker daemon is running and usable
- **kind** (Kubernetes in Docker): Cluster is set up, kubeconfig is configured
- **Linux**: Running on Linux (required for Buildah backend, kind, and e2e tests)
- **Container registry**: Registry is available for push/pull operations
  (note: `REGISTRY_STORAGE_DELETE_ENABLED=true` must be set on the registry
  for deletion-related tests)

Consequently, `task test:setup:environment` does NOT need to be run again.
During implementation via speckit commands, e2e and integration tests MUST
be executed directly without citing environment setup as a blocker.

## Governance

This constitution supersedes all other practices. Amendments require documentation and approval. All PRs/reviews must verify compliance with these rules. The `AGENTS.md` file contains the authoritative agent instructions derived from this constitution and `CODESTYLE.md`.

**Version**: 1.4.0 | **Ratified**: 2026-07-14 | **Last Amended**: 2026-08-10
