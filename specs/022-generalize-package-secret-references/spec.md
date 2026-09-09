# Feature Specification: Generalize Package Secret References

**Feature Branch**: `022-expand-package-secrets`

**Created**: 2026-09-09

**Status**: Draft

**Input**: User description: "Обобщить expand secrets: в рамках этой спецификации сделать только обобщение текущего частного решения для `PACKAGES_VERSION` и `REGISTRY`, чтобы build secrets можно было передавать в переменные окружения секции `packages.env`."

## Project Context

Delivery Kit generates package-install commands from the `packages` section of the build configuration. Build secrets are made available to the build stage as read-only files under `/run/secrets/<id>`, while `packages.env` currently treats every value as a literal environment value. As a result, a configuration value intended to refer to a secret file is passed as a file path instead of as the secret content.

The existing behavior has special handling for `PACKAGES_VERSION` and `REGISTRY`. This feature generalizes secret resolution: `REGISTRY` follows the same rules as any other secret, while `PACKAGES_VERSION` retains `metadata.ContainerFactoryVersionPath` as its default when no explicit secret reference is provided.

Git credentials and authentication configuration are explicitly excluded from this feature and will be specified separately.

## Clarifications

### Session 2026-09-09

- Q: How should a secret be identified in a `packages.env` value when the value equals `/run/secrets/<id>` or contains `${VARIABLE}`? → A: Only an exact `/run/secrets/<id>` reference is supported; `${VARIABLE}` inside `packages.env` is not expanded.
- Q: What should happen when `packages.env` contains an exact `/run/secrets/<id>` reference, but the secret is undeclared or its file is missing? → A: The build fails before the package manager starts; the secret content is not printed.
- Q: How do `REGISTRY` and `PACKAGES_VERSION` relate to the general secret-expansion logic? → A: `REGISTRY` is an ordinary secret and follows the general logic; the default for `PACKAGES_VERSION` is `metadata.ContainerFactoryVersionPath`.
- Q: If `packages.env` explicitly contains `/run/secrets/<id>` but an environment variable with the same name is already set, should the package manager receive the secret content? → A: Yes, the explicit secret reference takes precedence; without it, the ordinary environment is used, while `PACKAGES_VERSION` defaults to `metadata.ContainerFactoryVersionPath`.
- Q: When should an absent secret referenced by `packages.env` be reported? → A: During configuration parsing, before the build stage or package manager starts.

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Use Any Build Secret as a Package Environment Value (Priority: P1)

As a build configuration author, I want to pass the content of a declared build secret to a package manager through `packages.env`, so that package installation can use private registries or other sensitive configuration without writing custom shell commands for each variable.

**Why this priority**: This is the core gap described by the card. It removes the special-case limitation and makes the existing secret mechanism usable for all package ecosystems.

**Independent Test**: Define a build secret and reference its mounted path in `packages.env`, run a package stage with a package-manager substitute that records its environment, and verify that the recorded value is the secret content rather than the path.

**Acceptance Scenarios**:

1. **Given** a declared secret with ID `GOPROXY` whose mounted file contains a value, **when** `packages.env` assigns `GOPROXY` the value `/run/secrets/GOPROXY`, **then** the package manager receives the file content as `GOPROXY`.
2. **Given** a declared secret whose source is environment, file, or literal value, **when** it is referenced through `packages.env`, **then** the package manager receives the resolved secret content independently of the source type.
3. **Given** a regular `packages.env` value that is not a secret reference, **when** the package stage runs, **then** the package manager receives that value unchanged.

---

### User Story 2 - Keep Secret Resolution Ephemeral and Safe (Priority: P1)

As a build operator, I want secret expansion to exist only while the package manager runs, so that secrets are not persisted in the resulting image or exposed through generated commands and diagnostics.

**Why this priority**: Expanding secrets is useful only if it preserves the confidentiality guarantees of build secrets.

**Independent Test**: Run a package stage with a secret reference, inspect the generated command, logs, cache identity, and resulting image environment, and verify that the secret value appears only in the package manager process environment.

**Acceptance Scenarios**:

1. **Given** a secret-backed environment value, **when** the package command is generated, **then** the generated command contains no resolved secret content.
2. **Given** a package stage using secret expansion, **when** the stage completes, **then** the resolved secret is not persisted as an image environment value or build artifact.
3. **Given** a secret reference is undeclared or cannot be resolved from the configuration, **when** the configuration is parsed, **then** parsing fails with an actionable error identifying the unresolved reference without printing the secret value.

---

### Edge Cases

- A secret ID referenced by `packages.env` is not declared among the build secrets: fail during configuration parsing with a clear reference error; do not pass the path literally.
- A declared secret cannot be resolved from its configuration source: fail during configuration parsing without falling back to an arbitrary file path or silently passing an empty value.
- A secret value is empty: preserve the empty value as a valid resolved value; do not confuse it with an unresolved reference.
- A secret value contains spaces, quotes, newlines, shell metacharacters, or non-ASCII characters: pass it as one environment value without changing its content or executing it as shell syntax.
- A regular file-valued environment variable intentionally needs the literal path `/run/secrets/<id>`: this feature treats an exact path matching a declared secret ID as a secret-content reference; preserving arbitrary file paths remains outside this feature.

- A secret reference appears more than once: resolve it consistently for the stage and do not duplicate its content in commands or logs.
- `REGISTRY` is resolved through the same generalized secret-reference rules as every other secret.
- When no explicit secret reference supplies `PACKAGES_VERSION`, its default remains `metadata.ContainerFactoryVersionPath`.

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: The system MUST allow any declared build secret to be referenced by an exact `packages.env` value of `/run/secrets/<secret-id>`.
- **FR-002**: The system MUST resolve an exact secret-file reference to the content of the corresponding declared build secret before starting the package manager.
- **FR-003**: An explicit exact secret-file reference MUST take precedence over an already-set environment variable with the same name.
- **FR-004**: The system MUST preserve ordinary `packages.env` values that are not secret references without modification.
- **FR-005**: The system MUST treat only an exact `packages.env` value of `/run/secrets/<secret-id>` as a secret-content reference; variable-like text such as `${VARIABLE}` inside an environment value MUST remain literal text.
- **FR-006**: The system MUST reject references to undeclared or configuration-unresolvable secrets during configuration parsing, before the build stage or package-manager execution, with an actionable error that names the reference but never includes secret content.
- **FR-007**: The system MUST preserve secret content byte-for-byte as an environment value except for the existing secret-file reading convention already used by the build stage.
- **FR-008**: The system MUST keep resolved secret values out of generated command text, command arguments, logs, cache identity, SBOM data, build metadata, and persistent image environment.
- **FR-009**: The system MUST make resolved values available only to the package-stage process that needs them and its descendants, including the package manager.
- **FR-010**: The generalized behavior MUST cover all package directive types that consume `packages.env`; it MUST NOT require a variable-name-specific implementation branch.
- **FR-011**: When no explicit secret reference supplies `PACKAGES_VERSION`, the system MUST retain `metadata.ContainerFactoryVersionPath` as its default and preserve provenance file generation.
- **FR-012**: `REGISTRY` MUST use the generalized secret-reference behavior and MUST NOT require a variable-name-specific expansion branch.
- **FR-013**: This feature MUST NOT define or implement Git URL rewriting, credential injection, authentication configuration, or any other Git credentials/auth behavior.
- **FR-014**: The user-facing configuration MUST remain backward compatible for ordinary string values and existing configurations that do not use generalized secret expansion.

### Verification Requirements

- Tests MUST cover successful exact secret references for secrets sourced from environment, file, and literal value.
- Tests MUST cover unchanged ordinary values, exact secret references, repeated exact references, empty values, missing files, undeclared secrets, and shell-special characters.
- Tests MUST verify that the resolved value is not present in generated command text or diagnostics.
- Tests MUST verify compatibility for `PACKAGES_VERSION` and `REGISTRY`.
- Tests MUST include at least one package directive for a non-`os-pm` ecosystem to demonstrate that resolution is generic rather than tied to one variable or package manager.

### Key Entities

- **Build secret**: A declared secret identified by an ID and backed by an environment value, source file, or literal value; exposed to the build stage through its mounted secret file.
- **Package environment entry**: A name/value pair from `packages.env`, either an ordinary literal value or an exact secret-file reference.
- **Resolved package environment**: The ephemeral environment passed to the package manager after exact secret references have been evaluated.
- **Secret reference**: An exact `/run/secrets/<secret-id>` value that denotes the content of a declared build secret.
- **Variable-like text**: Text such as `${VARIABLE}` inside a package environment value; it is preserved literally and is not interpreted by this feature.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: For every supported package directive type, a declared secret referenced in `packages.env` reaches the package manager with the correct content in 100% of passing reference-resolution tests.
- **SC-002**: Existing configurations containing only ordinary `packages.env` values produce the same package-manager environment as before in the full compatibility test set.
- **SC-003**: Tests cover at least three secret source types and at least one non-`os-pm` package ecosystem, with no variable-name-specific setup beyond declaring the secret.
- **SC-004**: In all secret-expansion tests, zero resolved secret values occur in generated commands, logs, diagnostics, cache identity, SBOM data, or persistent image environment.
- **SC-005**: Undeclared or configuration-unresolvable secret references are detected during configuration parsing in 100% of negative tests, before the build stage or package manager starts; each failure identifies the missing reference without disclosing secret content.
- **SC-006**: `REGISTRY` passes the generalized secret-resolution tests, and `PACKAGES_VERSION` retains `metadata.ContainerFactoryVersionPath` as its default without requiring a variable-name-specific secret-expansion path.
- **SC-007**: A package stage using a secret containing shell-special characters passes the exact value to the package manager without command injection or content alteration.
- **SC-008**: When both an explicit `/run/secrets/<id>` reference and an existing environment value are present, the package manager receives the secret content; when the reference is absent, ordinary environment precedence remains unchanged.

## Assumptions

- Build secrets remain declared through the existing common `secrets` configuration and remain mounted at `/run/secrets/<id>` for the package stage.
- The exact mounted path `/run/secrets/<secret-id>` is the selected user-facing reference form for this specification; introducing a new `secret://` syntax or a separate aliases section is out of scope.
- `REGISTRY` is not a special case; it is an ordinary secret under the generalized rules. `metadata.ContainerFactoryVersionPath` remains the default for `PACKAGES_VERSION` when no explicit secret reference is provided.
- Text resembling `${VARIABLE}` is treated as a literal package environment value; composing values from secrets is out of scope for this feature.
- Secret values are allowed to contain newlines, subject to the existing environment and secret-file semantics of the build stage.
- Git credentials and authentication are separate work and will not be accepted as completion criteria for this feature.
- The implementation should remain internal to package-command generation unless planning identifies an existing shared expansion primitive that can be reused without enlarging the public API.
