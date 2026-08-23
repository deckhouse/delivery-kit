# Research: reject PM_LOCK_FILE override

## Decision: Reject `PM_LOCK_FILE` in `os-pm` directive validation

- **Decision**: Extend `pkg/config.PackagesDirective.validate` with an `os-pm`-specific check that rejects the presence of the exact environment key `PM_LOCK_FILE`, regardless of its value.
- **Rationale**: `rawPackagesDirective.toDirective` assigns the YAML `env` map and calls `PackagesDirective.validate` before a directive is returned. This is the earliest shared validation point for parsed configuration and therefore prevents package command generation and all subsequent build/SBOM work. Checking map-key presence, rather than value content, rejects custom, default, relative, and empty values uniformly.
- **Alternatives considered**:
  - Rejecting the key while formatting package commands: too late; invalid configuration could proceed into build execution and would not satisfy the validation boundary.
  - Rejecting `PM_LOCK_FILE` globally for all package types: violates the requirement that non-`os-pm` package configurations and their unrelated environment behavior remain unaffected.
  - Rewriting or deleting the variable: hides a configuration error and does not provide an explicit compatibility contract; the specification requires rejection with no compatibility mode.

## Decision: Reuse the existing SBOM metadata constant

- **Decision**: Reference `metadata.ContainerFactoryIndexPath` in the validation error and tests instead of introducing a second path constant.
- **Rationale**: `pkg/sbom/os_pm/metadata` already defines `/var/lib/pm/index.json`, and the `os-pm` collector reads through that constant. Reusing it prevents drift between validation messaging and effective SBOM collection.
- **Alternatives considered**:
  - Adding a config-local literal: duplicates an existing invariant and risks inconsistent future updates.
  - Adding a configurable path: conflicts with the feature’s safety objective and FR-005.

## Decision: Test at parsed configuration boundary with Ginkgo/Gomega

- **Decision**: Add table-driven/co-located Ginkgo tests for custom, default, and empty values; add acceptance cases for no `PM_LOCK_FILE`, unrelated `os-pm` variables, and non-`os-pm` variables.
- **Rationale**: Parsing through `rawPackagesDirective.toDirective` proves the rejection happens during configuration validation, while direct behavior assertions can verify unchanged command generation and fixed metadata path without requiring a container build.
- **Alternatives considered**:
  - E2E-only coverage: slower and less precise for a deterministic parser rule.
  - Standard-library tests/assertions: prohibited by the project constitution.

## Resolved technical unknowns

- **Validation location**: `pkg/config/packages_directive.go`, `PackagesDirective.validate`, called by `pkg/config/raw_packages_directive.go` during directive conversion.
- **SBOM path**: `/var/lib/pm/index.json`, represented by `metadata.ContainerFactoryIndexPath` and consumed by `pkg/sbom/packages/os_pm`.
- **External interface**: The user-facing YAML `packages[].env` configuration contract; no HTTP or generated API contract is involved.
- **Dependencies**: No new dependency is required.
