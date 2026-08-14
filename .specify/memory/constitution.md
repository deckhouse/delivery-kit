<!--
  Sync Impact Report
  Version: 1.5.5 → 1.5.6 (PATCH — remove redundant focused-command
  explanations)
  Modified principles: IV. Test-Before-Merge → IV. Test-Before-Merge
  Modified sections:
    - Build & Quality Gates: centralized build, lint, unit, e2e, integration,
      formatting, mock, and documentation commands; removed pm.lock generation
    - Environment Configuration: removed as a separate section; pre-configured
      test infrastructure is now stated in the test gate rules
  Removed sections:
    - Environment Configuration
  Templates requiring updates:
    - ✅ delivery-kit/AGENTS.md
    - ✅ delivery-kit/CLAUDE.md
    - ✅ delivery-kit/.specify/templates/constitution-template.md
    - ✅ delivery-kit/.specify/templates/plan-template.md
    - ✅ delivery-kit/.specify/templates/tasks-template.md
    - ✅ delivery-kit/.specify/templates/checklist-template.md
    - ✅ delivery-kit/CONTRIBUTING.md
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

Tests are co-located with source files (`*_test.go`). All tests MUST use Ginkgo +
Gomega; do not use the standard `testing` assertions or `testify`. Mocks MUST be
generated with `task mock:generate` — never write mocks by hand.

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

Use these commands instead of raw Go tooling:

- **Formatting**: `task format` (NOT raw `go fmt`/`gofmt`).
- **Build**: `task build` (NOT raw `go build`).
- **Lint**:
  - **Prerequisites (once per session)**: run
    `task deps:install:golangci-lint` before the first lint run in each new session.
  - **Usage**: after the prerequisite, run `task lint`. Do not invoke
    `golangci-lint` directly.
- **Unit tests**: `task test:unit` (NOT raw `go test`). Usage examples:
  - Scoped: `task test:unit paths="./pkg/sbom/..."`.
  - Focused: `task test:unit paths="./pkg/sbom/..." -- -focus=MyTest -v`.
  - **Prerequisites (once per session)**: the test environment is already prepared.
    Do not run or check `task test:setup:environment`, and do not skip e2e tests
    for setup reasons.
  - **Usage**: always run `task test:e2e` scoped with both `paths` and
    `labelFilter`. Examples:
    - Scoped: `task test:e2e paths="./test/e2e/sbom/..." labelFilter="sbom"`.
    - Focused: `task test:e2e paths="./test/e2e/sbom/..." labelFilter="sbom" -- -focus=MyTest -v`.
- **Integration tests**: run `task test:integration` directly against the prepared
  environment; do not run or check an environment setup command first.

- **Mocks**: `task mock:generate`; validate generated mocks with `task mock:check`.
- **Documentation**: run `task doc:gen` after changing CLI help text.

After every code change, run all gates.

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

**Version**: 1.5.6 | **Ratified**: 2026-07-14 | **Last Amended**: 2026-08-14
