# Research: Alternative Language Package Managers

## Scope

This research resolves the implementation choices for ephemeral Yarn, pnpm, uv, and Poetry installation in `packages` directives. The existing feature specification requires each alternative manager to be bootstrapped through npm or pip, used for a frozen dependency install, and removed after successful installation.

## Decision: Extend the existing file-based package directive

- Add a YAML `version` field to `rawPackagesDirective` and carry it through `FileBasedSpec`.
- Require `version` for `javascript-yarn`, `javascript-pnpm`, `python-uv`, and `python-poetry`.
- Reject `version` for primary package types and unsupported ecosystems rather than silently ignoring it.
- Keep the version scoped to one directive so multiple package directives cannot share bootstrap or cleanup state.

**Rationale:** `pkg/config` already owns package type validation, defaults, command generation, and SBOM metadata. Extending that model is smaller and preserves existing public behavior for `javascript-npm` and `python-pip`. A registry property centralizes alternative-manager classification where ecosystem metadata already lives.

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

## Decision: Wrap, isolate, install, and cleanup in one package-stage command sequence

Alternative-manager classification will use a switch helper over `PackagesDirectiveType`, returning true only for Yarn, pnpm, uv, and Poetry. The registry will not gain an `isAlternativeManager` field. A new internal command-wrapper type/factory will centralize the repeated `cd` and environment-prefix composition and return the install-command function used by `PackageEcosystem`. When the switch selects an alternative manager, the wrapper rejects a pre-installed executable, creates the ecosystem-specific ephemeral scope, and pairs its isolated executable with cleanup in the generated command sequence:

1. Check the original environment for the manager executable (`yarn`, `pnpm`, `uv`, or `poetry`) and fail with an explicit pre-installed-manager error if it is found.
2. Create a unique directive-local scope according to the ecosystem: JavaScript uses an npm prefix; Python uses a venv.
3. Emit one complete `if ... then ... else ... fi` block per ecosystem. The `then` branch rejects the pre-installed executable. The `else` branch keeps scope creation, exact-version installation and verification, frozen dependency installation, and cleanup on separate readable lines under fail-fast shell execution. Do not prepend the temporary scope to a process-global `PATH`.

The primary manager is not bootstrapped for `javascript-npm` or `python-pip`, and those generated commands remain unchanged.

**Rationale:** `PackagesStage` already has network access, command content participates in `PackagesChecksum`, and one conditional block per ecosystem keeps each lifecycle self-contained. Rejecting an executable already present in the image enforces one deterministic installation path and avoids ambiguous version/state ownership. A prefix or virtual environment makes a newly installed manager available independently of the project workdir. Absolute executable paths avoid `PATH` leakage between directives. Fail-fast shell execution ensures a failed bootstrap or dependency step prevents later steps, while cleanup runs only after successful dependency installation and remains diagnosable if it fails.

**Alternatives considered:** A new build stage would duplicate stage/cache plumbing and make per-directive cleanup harder. A project-local installation could pollute the project dependency tree. A shared global npm prefix or system Python installation would violate isolation and make cleanup unsafe. Reusing an image-provided manager was rejected for this phase because it makes exact-version ownership and cleanup semantics ambiguous. A registry boolean would duplicate the type classification and add metadata that can drift from the supported-type switch. Separate install and cleanup callbacks would split one lifecycle result; the wrapper keeps the executable and matching cleanup command together while centralizing repeated shell composition.

## Decision: Preserve existing lock and SBOM behavior

Keep `--frozen-lockfile` for Yarn/pnpm, `uv sync --frozen`, and `poetry sync --no-root`. Existing spec/lock paths continue to feed managed-input catalogers and package-stage cache dependencies. The temporary manager is removed, not the installed project dependencies or manifest/lock files, so SBOM scanning still sees the same project state.

**Rationale:** The feature changes manager availability, not dependency semantics or cataloger definitions. Existing e2e tests already exercise Yarn, pnpm, uv, and Poetry SBOM output.

**Alternatives considered:** Adding an independent lock validator would duplicate package-manager behavior. Removing dependency artifacts to clean up the manager would violate SBOM coverage and alter image behavior. The wrapper removes only its ephemeral manager scope.

## Decision: Test at configuration, command, stage, and e2e levels

Add Ginkgo/Gomega tests for version parsing and validation, generated bootstrap/use/cleanup ordering, exact version propagation, primary-manager non-regression, and independent multiple directives. Retain and update the four existing manager e2e scenarios and fixtures to specify exact versions, verify the builder images do not preinstall alternatives, verify pre-installed alternatives are rejected where fixture coverage is available, and verify that successful output remains SBOM-visible.

**Rationale:** Unit tests provide deterministic coverage of shell generation and validation; e2e tests prove the real package managers, builder images, cleanup, and SBOM path.

**Alternatives considered:** Adding only e2e tests would leave malformed configuration and failure ordering weakly covered; adding only unit tests would not prove package-manager behavior in container builds.
