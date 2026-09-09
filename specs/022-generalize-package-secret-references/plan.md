# Implementation Plan: Generalize Package Secret References

**Branch**: `022-generalize-package-secret-references` | **Date**: 2026-09-09 | **Spec**: [spec.md](./spec.md)

**Input**: Feature specification from `specs/022-generalize-package-secret-references/spec.md`

> The feature spec's embedded branch label is `022-expand-package-secrets`; the setup script selected `022-generalize-package-secret-references` and this plan follows the setup output.

## Summary

Generalize package-stage environment handling so any declared build secret can be referenced by an exact `packages.env` value of `/run/secrets/<secret-id>`. Configuration parsing will validate that the reference is declared and that its configured source can be resolved before a build stage is created. Package command generation will receive only validated secret metadata/IDs, emit a single-line inline environment prefix, and read the already-validated mounted value only for the package-manager process. Ordinary values and `${VARIABLE}` text remain literal. Existing `PACKAGES_VERSION` provenance behavior and compatible `REGISTRY` handling are preserved through the shared resolver without adding more variable-name-specific expansion branches.

## Technical Context

**Language/Version**: Go 1.24.10

**Primary Dependencies**:
- Go standard library for command generation, sorting, quoting, and path handling.
- Existing `samber/lo` helpers in `pkg/config`.
- Existing Buildah/Stapel secret mount path implementation in `pkg/build/secrets`.
- Existing Ginkgo/Gomega test harness.

**Storage**: No new storage. Secrets remain read-only stage mounts at `/run/secrets/<id>`; resolved values are process-local.

**Testing**: Co-located Ginkgo/Gomega unit tests, focused package-stage tests, and an e2e fixture only where runtime package-manager delivery cannot be proven by unit tests.

**Target Platform**: Linux build stages using the existing Bash-compatible package command execution path.

**Project Type**: Go CLI with package configuration and image-build libraries.

**Performance Goals**: Preserve current package command generation overhead; resolve each referenced mounted file only while the package manager runs.

**Constraints**:
- Do not add external dependencies.
- Do not expose secret contents to Go-generated command strings, diagnostics, cache identity, SBOM data, metadata, or persistent image environment.
- Preserve ordinary `packages.env` behavior and existing `PACKAGES_VERSION`/`REGISTRY` compatibility.
- Do not implement Git credentials, authentication configuration, or URL rewriting.

**Scale/Scope**: Internal changes primarily in `pkg/config/packages_commands.go`, package ecosystem command wiring, and `pkg/config/raw_stapel_image.go`, with focused tests in `pkg/config` and any required package-stage/e2e fixture coverage.

## Constitution Check

*GATE: Must pass before Phase 0 research. Re-check after Phase 1 design.*

- **I. Simplicity Over Abstraction**: PASS. Reuse the existing package command pipeline and secret mounts. Add one small internal resolver/options path rather than a new public service or package.
- **II. Go Idiomatic Code**: PASS. Changes remain internal to configuration conversion and command generation; errors will be wrapped with context and guard clauses will be preferred.
- **III. Minimal Public Surface**: PASS. No public CLI/API contract changes. Secret values are never added to generator inputs.
- **IV. Test-Before-Merge**: PASS. Tests remain co-located and use Ginkgo/Gomega; runtime and negative cases are explicitly planned.
- **V. Conventional Commits**: PASS for implementation planning; no commit or branch mutation is performed by this workflow.
- **Dependency Rules**: PASS. No new dependency and no cross-layer boundary change.
- **Build/quality gates**: PASS. Validation will use `task format`, `task build`, `task deps:install:golangci-lint`, `task lint`, `task test:unit`, scoped `task test:e2e`, and `task test:integration` according to repository rules.

**Gate status before research**: PASS.

## Research Summary

Detailed findings are in [research.md](./research.md). Key conclusions:

1. Package commands are generated in `pkg/config/raw_stapel_image.go` after validated image secrets are available, so reference validation belongs in the configuration conversion path before command generation.
2. All ecosystems already share an environment map and inline-prefix convention, so one resolver can cover `os-pm` and non-`os-pm` directives.
3. The configuration layer validates source resolution without passing secret contents into generated commands; the stage still reads the mounted value only while invoking the package manager.
4. Both undeclared references and configuration-unresolvable secret sources fail during parsing; no runtime diagnostic branch is generated for missing secrets.
5. `PACKAGES_VERSION` provenance and compatibility defaults must be retained without making them the general expansion mechanism.

## Design

### Package command generation

- Introduce an internal options value for package command generation containing declared secret IDs, following the repository's options-struct convention where appropriate.
- Pass the IDs derived from `imageBase.Secrets` when `rawStapelImage.toStapelImageBaseDirective` calls `GeneratePackagesCommands`.
- Keep `config.Secret` source values and resolved contents out of this API.

### Generic environment serialization

- Replace the current unconditional `formatEnvVars` path for package environments with a common resolver/formatter.
- During configuration conversion, parse exact `/run/secrets/<id>` references, require `<id>` to be declared, and validate that the declared secret source can be resolved using the existing secret-source validation path. Return an actionable configuration error without secret content when validation fails.
- Sort names as today.
- For each value:
  - If it is an exact validated secret reference, format an inline shell assignment that reads the mounted file.
  - If it is not an exact reference, serialize it as the existing literal value; `${VARIABLE}` remains literal.
- Ensure explicit references assign the target variable after any inherited value would otherwise be considered, so the explicit reference wins.
- Keep the resulting command as one single-line shell command in the existing `ENV_VAR=value command` shape. Do not generate multiline scripts, standalone exports, or runtime missing-secret checks.
- Reuse the same primitive for compatibility handling of `PACKAGES_VERSION` and `REGISTRY`; do not add variable-specific generalized branches.

### Configuration validation and runtime behavior

- Validate undeclared references and unresolvable configured secret sources during configuration parsing, before the build stage or package manager starts.
- Reuse the existing source-specific checks for environment, file, and literal secrets; preserve empty values as valid values rather than treating them as unresolved.
- Errors identify the unresolved reference or source, but never print secret contents.
- After validation, the generated single-line command reads the mounted secret only into the package-stage process environment and its descendants.
- Do not emit runtime missing-secret checks or fallback-to-path behavior.
- No resolved values are written to generated commands, command arguments, logs, stage checksums, SBOM output, metadata, or image environment.

### Compatibility behavior

- Preserve `PACKAGES_VERSION`'s required provenance-file write to `metadata.ContainerFactoryVersionPath` when no explicit package environment reference supplies it.
- Preserve existing ordinary values and configurations with no secret references.
- Preserve existing implicit `REGISTRY` behavior where required for compatibility, while routing secret reads through the generic file-reference primitive.
- Explicit `packages.env` references take precedence over inherited same-name environment values and compatibility fallbacks.

### Testing strategy

Extend `pkg/config/packages_commands_test.go` to cover:

- Environment-, file-, and literal-backed declared secrets.
- Exact references, repeated references, empty values, shell-special characters, and ordinary values.
- Literal `${VARIABLE}` values and non-reference paths.
- Undeclared references and configuration-unresolvable environment/file/literal sources failing during configuration parsing, before package-manager execution.
- No resolved content in generated command strings or errors.
- `os-pm`, plus at least one non-`os-pm` ecosystem such as `go-mod` or `python-pip`.
- `PACKAGES_VERSION` provenance and `REGISTRY` compatibility.

Use package-stage or focused e2e coverage where necessary to demonstrate that a package-manager substitute receives the resolved environment through the single-line `ENV_VAR=value command` form and that the value does not persist in the resulting image.

## Project Structure

### Documentation (this feature)

```text
specs/022-generalize-package-secret-references/
├── plan.md
├── research.md
├── data-model.md
├── contracts/              # Intentionally empty: no external interface is added
└── quickstart.md
```

`tasks.md` is intentionally not created by this workflow; it belongs to the subsequent `/speckit-tasks` phase.

### Source Code (expected implementation areas)

```text
pkg/config/
├── packages_commands.go       # Generic reference-aware environment formatting
├── packages_directive.go      # Pass formatting options to all ecosystems
├── raw_stapel_image.go        # Supply declared secret IDs during generation
└── packages_commands_test.go  # Unit and shell-level behavior coverage

pkg/build/stage/               # Only if package-stage runtime coverage needs extension
test/e2e/sbom/                 # Only if a mounted-stage fixture is required
```

**Structure Decision**: Keep the implementation in the existing `pkg/config` package-command path. Do not introduce a new package or public interface.

## Phase 1 Constitution Re-check

- Simplicity: PASS; the design reuses existing mounts and command execution.
- Minimal public surface: PASS; no public API or configuration syntax change.
- **Security: PASS by construction; source availability is validated during configuration parsing, while secret contents remain absent from command text and persistent outputs.
- Compatibility: PASS; ordinary values and the existing `PACKAGES_VERSION`/`REGISTRY` behavior are explicit design constraints.
- Testing: PASS; required positive, negative, source-type, ecosystem, compatibility, and no-leak cases are mapped to co-located tests.
- Scope: PASS; Git credentials and authentication remain excluded.

**Gate status after Phase 1 design**: PASS.

## Complexity Tracking

No constitution violations or justified complexity exceptions identified.
