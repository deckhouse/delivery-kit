# Research: Generalize Package Secret References

## Decision 1: Resolve references in generated package-stage shell commands

**Decision**: Keep secret-value expansion in the shell command executed by the package stage, but validate the reference and configured source during configuration parsing. The generator emits only the mounted path and inline shell syntax; it never reads or embeds secret contents or emits runtime missing-secret checks.

**Rationale**:
- Build secrets are already mounted read-only at `/run/secrets/<id>` for the stage.
- The existing package commands already run in that stage and use Bash-compatible syntax.
- Runtime expansion keeps secret contents out of generated command text, stage command checksums, logs derived from commands, and persistent image configuration, while configuration-time validation catches unavailable sources before stage creation.
- Both legacy and current Stapel execution paths consume the same generated package commands and mounted secret volumes.

**Alternatives considered**:
- Resolve secrets in Go before command generation: rejected because it would expose secret contents to configuration objects, command strings, or cache inputs.
- Add a new public secret-resolution API: rejected because the feature is internal to package command generation and the existing mount mechanism is sufficient.

## Decision 2: Pass only declared secret identifiers to package command generation

**Decision**: Extend package command generation with internal options containing the set of declared secret IDs, and pass that set from `rawStapelImage.toStapelImageBaseDirective` after validated secrets are loaded. Do not pass secret values.

**Rationale**:
- The generator must distinguish an exact declared reference from an ordinary string and reject undeclared references before the package manager starts.
- `imageBase.Secrets` already contains validated declarations at the point where package commands are generated.
- Passing identifiers preserves the minimal surface and prevents accidental secret-value propagation.

**Alternatives considered**:
- Validate references while parsing `packages.env`: rejected because parsing does not have the image's validated secret declarations available.
- Pass full `config.Secret` objects: rejected because source metadata is unnecessary for command generation and increases coupling.
- Move command generation into the builder: rejected because it is a larger lifecycle change and would duplicate configuration behavior.

## Decision 3: Use one generic environment-entry resolver for all package ecosystems

**Decision**: Replace the unconditional environment serializer with a resolver applied to every `packages.env` entry. An exact value `/run/secrets/<id>` is a secret reference only when it matches the supported reference form; the ID must be declared. All other values, including `${VARIABLE}` text, remain literal values and retain existing ordering and shell-quoting behavior.

**Rationale**:
- Every ecosystem already receives an environment map through the common `InstallCmd` signature.
- A single resolver satisfies the requirement that behavior not branch on variable names and covers `os-pm` and non-`os-pm` directives.
- Exact matching avoids introducing variable interpolation or partial/path composition semantics.

**Alternatives considered**:
- Special-case `PACKAGES_VERSION`, `REGISTRY`, or common registry variables: rejected because it preserves the limitation the feature is intended to remove.
- Interpret any `/run/secrets/...` substring: rejected because ordinary values must remain unchanged and only exact references are specified.

## Decision 4: Fail safely for undeclared or unavailable references

**Decision**: Reject an exact reference to an undeclared secret and a declared secret whose configured source cannot be resolved during configuration parsing. Error text may identify the reference or source but must not contain secret content. Empty values remain valid values.

**Rationale**:
- Both declaration errors and source-resolution errors can be detected before a stage is launched, producing an actionable configuration error.
- The existing secret-source validation path already checks environment and file sources before mount creation; literal values are available directly.
- No runtime error branch is needed for an absent configured secret, keeping the generated command single-line and limited to inline environment assignment.

**Alternatives considered**:
- Silently treat unresolved sources as empty: rejected by the specification and unsafe because it can make authentication fail ambiguously.
- Defer the error to generated shell code: rejected because the updated specification requires configuration parsing to fail first.
- Fall back to passing the path literally: rejected because it leaks an unintended path to the package manager and violates explicit-reference semantics.

## Decision 5: Preserve compatibility defaults for `PACKAGES_VERSION` and `REGISTRY`

**Decision**: Keep the existing `PACKAGES_VERSION` fallback/provenance-file behavior when no explicit `packages.env` entry supplies a secret reference. Preserve existing `REGISTRY` behavior for configurations that rely on its implicit package-stage environment, but implement its secret read through the same generic environment-resolution primitive rather than a new name-specific resolver.

**Rationale**:
- `PACKAGES_VERSION` is required for SBOM provenance and must continue to write `metadata.ContainerFactoryVersionPath`.
- Existing configurations may rely on implicit `PACKAGES_VERSION` and `REGISTRY` environment handling.
- Explicit `packages.env` references must take precedence over an existing environment variable and must not be overwritten by the compatibility fallback.

**Alternatives considered**:
- Remove implicit `REGISTRY` handling: rejected because it risks breaking existing configurations and conflicts with backward compatibility.
- Keep separate `formatSecretVar("REGISTRY")` and `formatSecretVar("PACKAGES_VERSION")` logic as the general solution: rejected because it leaves variable-name-specific expansion in place. Compatibility defaults may remain, but their file reads should use the generic primitive.

## Decision 6: Validate through focused unit tests plus a package-stage integration scenario

**Decision**: Extend `pkg/config/packages_commands_test.go` for command shape, generic coverage, error/no-leak behavior, and shell execution of mounted files. Add or extend a focused package-stage/e2e fixture only if needed to prove actual package-manager environment delivery, including a non-`os-pm` ecosystem.

**Rationale**:
- Existing unit tests already cover all package directive types and shell execution of the current secret helper.
- The independent behavior is runtime resolution, so command-string assertions alone are insufficient.
- The specification requires three secret source types, negative cases, shell-special values, repeated references, compatibility defaults, and a non-`os-pm` directive.

**Alternatives considered**:
- Only update generated-command string tests: rejected because they cannot prove the package manager receives secret content.
- Add a broad end-to-end suite first: rejected because the smallest reliable regression coverage belongs beside package command generation; use e2e only for the final mounted-stage path that unit tests cannot model.

## Repository constraints confirmed

- Business logic belongs under `pkg/config`; no new external dependency is needed.
- Generated package commands remain single-line inline-environment commands in the form `ENV_VAR=value command`.
- Tests are co-located and use Ginkgo/Gomega.
- Package commands are generated in `pkg/config/raw_stapel_image.go` and executed through the existing `Shell.Packages` stage path.
- Secret mounts are provided by `pkg/build/secrets`, so this feature does not change secret storage or mount semantics.
- Git credentials, authentication configuration, and URL rewriting remain out of scope.
