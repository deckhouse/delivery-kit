# Feature Specification: Enforce a Single os-pm Directive

**Feature Branch**: `016-single-os-pm`

**Created**: 2026-08-20

**Status**: Draft

**Input**: User description: "In werf.yaml, reject using multiple packages sections of type os-pm because this creates nondeterminism risks"

## Project Context

Delivery Kit is a CLI tool for building and delivering applications. The `werf.yaml` configuration supports package directives, including `os-pm` for installing operating-system packages.

## User Scenarios & Testing

### User Story 1 - Reject multiple os-pm directives (Priority: P1)

As a configuration author, I want validation to reject multiple `packages` directives of type `os-pm`, so that builds do not depend on ambiguous processing order and remain reproducible.

**Why this priority**: Multiple `os-pm` directives can create ambiguity in package installation order and produce different build results, which threatens deterministic builds.

**Independent Test**: Provide a configuration containing two `packages` directives with `type: os-pm` and verify that validation rejects the configuration before the build starts.

**Acceptance Scenarios**:

1. **Given** a configuration contains one `packages` directive with `type: os-pm`, **When** the configuration is validated, **Then** validation succeeds.
2. **Given** a configuration contains two or more `packages` directives with `type: os-pm`, **When** the configuration is validated, **Then** validation fails with a clear message stating that only one `os-pm` directive is allowed.
3. **Given** a configuration contains multiple package directives of other types and one `os-pm` directive, **When** the configuration is validated, **Then** validation succeeds.
4. **Given** a configuration contains no `os-pm` directives, **When** the configuration is validated, **Then** its behavior remains unchanged.

---

### User Story 2 - Identify the configuration error clearly (Priority: P2)

As a configuration author, I want the validation error to identify the `os-pm` multiplicity violation, so that I can correct the configuration without investigating a later build failure.

**Why this priority**: Actionable diagnostics reduce the time required to correct invalid configuration and make the new restriction understandable.

**Independent Test**: Validate a configuration with multiple `os-pm` directives and verify that the error identifies the violated single-directive rule and points to the `packages` configuration.

**Acceptance Scenarios**:

1. **Given** a configuration contains multiple `os-pm` directives, **When** validation fails, **Then** the error identifies `os-pm` and states that no more than one such directive is permitted.
2. **Given** a configuration contains multiple `os-pm` directives with different `workdir`, `spec`, or `lock` values, **When** the configuration is validated, **Then** the same multiplicity rule is applied regardless of those values.

## Edge Cases

- Multiple `os-pm` directives may appear in any positions in the `packages` list; validation must not depend on their order.
- Multiple directives of other package types must not be rejected by this rule.
- The restriction applies even when multiple `os-pm` directives use different `workdir`, `spec`, or `lock` values.
- Invalid configuration must be rejected before package installation or other build operations begin.
- A configuration with exactly one `os-pm` directive must retain its existing validation and build behavior.

## Requirements

### Functional Requirements

- **FR-001**: The system MUST allow no more than one `packages` directive with type `os-pm` in a single `werf.yaml` configuration.
- **FR-002**: The system MUST reject a configuration containing two or more `os-pm` directives.
- **FR-003**: The validation error MUST identify the `os-pm` directive and state that only one `os-pm` directive is allowed.
- **FR-004**: The validation MUST run before package installation and other build operations begin.
- **FR-005**: The system MUST continue to allow multiple package directives whose types are not `os-pm`.
- **FR-006**: The system MUST preserve the current behavior for configurations containing zero or one `os-pm` directive.
- **FR-007**: The validation result MUST be independent of the order of package directives and of the individual `os-pm` values.

## Key Entities

- **Package directive**: An item in the `packages` section of `werf.yaml` that describes how a dependency ecosystem is managed.
- **os-pm directive**: A package directive used to install operating-system packages through the OS package manager.

## Success Criteria

### Measurable Outcomes

- **SC-001**: 100% of valid configurations containing zero or one `os-pm` directive pass the new multiplicity validation.
- **SC-002**: 100% of configurations containing two or more `os-pm` directives are rejected before package installation begins.
- **SC-003**: Configurations containing multiple package directives of other types do not fail because of the `os-pm` multiplicity rule.
- **SC-004**: Every rejected configuration with multiple `os-pm` directives produces an actionable error that names `os-pm` and the one-directive limit.
- **SC-005**: Permuting the order of the same package directives produces the same validation result.

## Assumptions

- Users who need to install several sets of operating-system packages will combine them into one `os-pm` directive.
- The restriction applies within a single `werf.yaml` configuration.
- The change does not alter the format or behavior of a valid single `os-pm` directive.
- The restriction does not apply to package types other than `os-pm`.
