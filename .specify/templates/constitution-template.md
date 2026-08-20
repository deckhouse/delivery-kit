# Delivery Kit Constitution

## Core Principles

### I. Simplicity Over Abstraction

Prefer stupid and simple over abstract and extendable. Prefer a bit of duplication over complex abstractions. Minimize interfaces, generics, and embedding. Prefer functions over methods, public fields over getters/setters, and data types over types with behavior.

### II. Go Idiomatic Code

Follow Effective Go and Go Code Review Comments. All public functions MUST accept `context.Context` as the first parameter. Errors MUST be wrapped with context using `fmt.Errorf("doing something: %w", err)`. Use guard clauses and early returns. Never use `this`/`self` as receiver names, never use named returns, never use dot imports.

### III. Minimal Public Surface

Keep everything private/internal as much as possible. Validate early, validate a lot. Keep APIs stupid and minimal. When in doubt, don't add comments — only document non-obvious public APIs or genuinely non-obvious logic.

### IV. Test-Before-Merge

Tests are co-located with source files (`*_test.go`) and MUST use Ginkgo + Gomega. Mocks MUST be generated with `task mock:generate`.

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

- **Formatting**: `task format` (NOT raw `go fmt`/`gofmt`)
- **Build**: `task build` (NOT raw `go build`)
- **Lint**:
  - **Prerequisites (once per session)**: run
    `task deps:install:golangci-lint` before the first lint run.
  - **Usage**: then run `task lint`.
- **Unit tests**: `task test:unit` (NOT raw `go test`). Usage examples:
  - Scoped: `task test:unit paths="./pkg/sbom/..."`.
  - Focused: `task test:unit paths="./pkg/sbom/..." -- -focus=MyTest -v`.
- **E2E tests**:
  - **Prerequisites (once per session)**: the environment is already prepared. Do
    not run or check `task test:setup:environment` or skip e2e tests for setup reasons.
  - **Usage**: always run `task test:e2e` scoped with both `paths` and `labelFilter`.
    - Scoped: `task test:e2e paths="./test/e2e/..." labelFilter="..."`.
    - Focused: `task test:e2e paths="./test/e2e/..." labelFilter="..." -- -focus=MyTest -v`.
- **Integration tests**: run `task test:integration` directly against the prepared environment.
- **Mocks**: `task mock:generate`; validate with `task mock:check`.
- **Documentation**: `task doc:gen` after changing CLI help text.

## Governance

This constitution supersedes all other practices. Amendments require documentation and approval. All PRs/reviews must verify compliance with these rules. The `AGENTS.md` file contains the authoritative agent instructions derived from this constitution and `CODESTYLE.md`.

**Version**: 1.0.0 | **Ratified**: 2026-07-14 | **Last Amended**: 2026-07-14