# Research: Alternative Language Package Managers

## Scope

This research resolves the implementation choices for ephemeral Yarn, pnpm, uv, and Poetry installation in `packages` directives. The existing feature specification requires each alternative manager to be bootstrapped through npm or pip, used for a frozen dependency install, and removed after successful installation.

## Decision: Extend the existing file-based package directive

- Add a YAML `version` field to `rawPackagesDirective` and carry it through `FileBasedSpec`.
- Require `version` for `javascript-yarn`, `javascript-pnpm`, `python-uv`, and `python-poetry`.
- Reject `version` for primary package types and unsupported ecosystems rather than silently ignoring it.
- Keep the version scoped to one directive so multiple package directives cannot share bootstrap or cleanup state.

**Rationale:** `pkg/config` already owns package type validation, defaults, command generation, and SBOM metadata. Extending that model is smaller and preserves existing public behavior for `javascript-npm` and `python-pip`.

**Alternatives considered:** A separate top-level manager configuration would make version/cleanup state global and complicate multiple workdirs. A generic package-manager interface would add abstraction without reducing the four concrete command sequences.

## Decision: Use `version` with exact `X.Y.Z` validation

The wire format is, for example:

```yaml
packages:
  - type: javascript-yarn
    workdir: /app
    version: 1.22.22
```

The parser stores the field as a string and validates a non-empty exact semantic version with three numeric components (`X.Y.Z`). Version ranges, tags, prefixes, empty values, and malformed values are rejected during configuration parsing.

**Rationale:** The specification explicitly requires an exact version and rejects omitted versions. A string avoids YAML numeric coercion while retaining the user-provided version for command generation.

**Alternatives considered:** Generic semver libraries or ranges are unnecessary for the stated contract and could accept values the package-manager bootstrap command cannot reproduce. A field named `managerVersion` is more explicit but inconsistent with the concise directive keys and the feature’s established `version` terminology.

## Decision: Bootstrap, install, and cleanup in one package-stage command sequence

`GeneratePackagesCommands` will generate one ordered shell sequence per alternative directive:

1. Verify the alternative-manager executable is absent; fail with an actionable pre-existing-manager error if found.
2. Use npm or pip to install the exact requested manager version.
3. Run the existing frozen dependency-install command.
4. Remove only the manager installation created by this sequence; cleanup success is required.

The primary manager is not bootstrapped for `javascript-npm` or `python-pip`, and those generated commands remain unchanged.

**Rationale:** `PackagesStage` already has network access, command content participates in `PackagesChecksum`, and a single sequence preserves failure ordering. Shell `&&` sequencing ensures dependency failure returns the original error and prevents successful-install cleanup from masking it.

**Alternatives considered:** A new build stage would duplicate stage/cache plumbing and make per-directive cleanup harder. A general cleanup abstraction would be premature; the four manager-specific bootstrap and cleanup commands can be generated directly from the ecosystem registry.

## Decision: Preserve existing lock and SBOM behavior

Keep `--frozen-lockfile` for Yarn/pnpm, `uv sync --frozen`, and `poetry sync --no-root`. Existing spec/lock paths continue to feed managed-input catalogers and package-stage cache dependencies. The temporary manager is removed, not the installed project dependencies or manifest/lock files, so SBOM scanning still sees the same project state.

**Rationale:** The feature changes manager availability, not dependency semantics or cataloger definitions. Existing e2e tests already exercise Yarn, pnpm, uv, and Poetry SBOM output.

**Alternatives considered:** Adding an independent lock validator would duplicate package-manager behavior. Removing dependency artifacts to clean up the manager would violate SBOM coverage and alter image behavior.

## Decision: Test at configuration, command, stage, and e2e levels

Add Ginkgo/Gomega tests for version parsing and validation, generated bootstrap/use/cleanup ordering, exact version propagation, primary-manager non-regression, and independent multiple directives. Retain and update the four existing manager e2e scenarios and fixtures to specify exact versions and verify the builder images do not preinstall alternatives and that successful output remains SBOM-visible.

**Rationale:** Unit tests provide deterministic coverage of shell generation and validation; e2e tests prove the real package managers, builder images, cleanup, and SBOM path.

**Alternatives considered:** Adding only e2e tests would leave malformed configuration and failure ordering weakly covered; adding only unit tests would not prove package-manager behavior in container builds.
