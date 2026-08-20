# Research: Enforce a Single os-pm Directive

## Decision: Validate multiplicity during raw image-to-directive conversion

- **Decision**: Count `packages` entries whose raw `type` is `os-pm` in `rawStapelImage.toStapelImageBaseDirective` before converting entries and generating package-install commands. Return a detailed configuration error when the count exceeds one.
- **Rationale**: This is the earliest point where the complete `packages` list for an image is available and the existing configuration conversion already returns validation errors. It rejects invalid configurations before `GeneratePackagesCommands` and before build stages execute. Counting raw types makes the rule independent of package values, `workdir`, `spec`, `lock`, `env`, and list ordering.
- **Alternatives considered**:
  - Validate in `PackagesDirective.validate`: rejected because that method validates one directive and cannot enforce a list-level cardinality rule without introducing unrelated global state or changing its API.
  - Validate in `GeneratePackagesCommands`: rejected because command generation is downstream of configuration validation and is also used directly by lower-level tests/callers; it would allow invalid configuration farther into the build pipeline.
  - Validate in YAML unmarshalling: rejected because the raw directive’s custom unmarshalling runs per item and does not own the complete list; list-level conversion has clearer access to the parent image and existing detailed-error context.

## Decision: Preserve command generation for the lower-level API

- **Decision**: Do not change `GeneratePackagesCommands` or its existing behavior for multiple `os-pm` values supplied directly.
- **Rationale**: The feature constrains valid `werf.yaml` configurations, while command generation is a lower-level transformation. Keeping it unchanged avoids an unnecessary API behavior change and preserves focused unit tests that verify one command per input directive.
- **Alternatives considered**:
  - Make `GeneratePackagesCommands` reject or merge multiple `os-pm` entries: rejected because it has no error return and would broaden the feature beyond configuration validation.

## Decision: Use a detailed error naming the packages section and limit

- **Decision**: Report an error containing `packages`, `os-pm`, and that only one directive is allowed, using the existing `newDetailedConfigError` mechanism with the source document.
- **Rationale**: Existing configuration errors include actionable messages and rendered source context. The required terms make the failure recognizable in CLI output while preserving the repository’s diagnostics convention.
- **Alternatives considered**:
  - Generic `fmt.Errorf`: rejected because it would omit the source document context available at the parser boundary.

## Resolved technical context

- Language: Go 1.24.10.
- Feature area: `pkg/config`, specifically raw package directive conversion in `raw_stapel_image.go`.
- Tests: co-located Ginkgo/Gomega tests in `pkg/config` (and, if needed, the existing parser/config test helpers).
- Dependencies: no new dependencies.
- External contracts: none; the user-visible contract is documented in `contracts/config-validation.md`.
