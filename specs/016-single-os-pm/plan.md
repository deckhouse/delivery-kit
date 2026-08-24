# Implementation Plan: Enforce a Single os-pm Directive

**Branch**: `016-single-os-pm` | **Date**: 2026-08-20 | **Spec**: [spec.md](spec.md)

**Input**: Feature specification from `specs/016-single-os-pm/spec.md`

## Summary

Reject a `werf.yaml` image configuration when its `packages` list contains more than one `os-pm` directive. Implement list-level cardinality validation in `pkg/config` before package directives are converted and before package-install commands are generated, while leaving lower-level command generation and valid configurations unchanged.

## Technical Context

**Language/Version**: Go 1.24.10

**Primary Dependencies**: Existing `pkg/config` parser and YAML model; no new dependencies.

**Storage**: Existing rendered `werf.yaml` configuration and in-memory raw directive model; no storage changes.

**Testing**: Ginkgo + Gomega, co-located with `pkg/config` source/tests.

**Target Platform**: Existing werf CLI platforms; validation is platform-independent.

**Project Type**: Go CLI tool; configuration parsing is in `pkg/config`.

**Performance Goals**: O(n) scan of each image’s `packages` list; no meaningful change to normal configuration parsing cost.

**Constraints**: Reject invalid configuration before package installation/build operations; preserve zero/one `os-pm` behavior and repeatability of non-`os-pm` directives; do not add dependencies or modify generated files.

## Constitution Check

*GATE: Must pass before Phase 0 research. Re-check after Phase 1 design.*

- **I. Simplicity Over Abstraction**: PASS — one local cardinality check at the existing conversion boundary; no new abstraction or interface.
- **II. Go Idiomatic Code**: PASS — use existing error and guard-clause patterns; no public API changes.
- **III. Minimal Public Surface**: PASS — keep validation internal to `pkg/config`; do not change exported command-generation APIs.
- **IV. Test-Before-Merge**: PASS — add co-located Ginkgo/Gomega coverage for valid, invalid, ordering, and unaffected directive cases.
- **V. Conventional Commits**: PASS — no commit or branch operation is part of this plan; branch is already `016-single-os-pm`.
- **Code boundaries**: PASS — parser/model work stays in `pkg/config`; tests stay alongside it.
- **Dependency rules**: PASS — no new external dependencies.
- **Quality gates**: PASS — implementation validation will use `task format`, `task build`, lint prerequisites/lint, unit tests, scoped e2e, and integration tests as applicable.

## Project Structure

### Documentation (this feature)

```text
specs/016-single-os-pm/
├── plan.md
├── research.md
├── data-model.md
├── quickstart.md
├── contracts/
│   └── config-validation.md
└── tasks.md              # created later by /speckit-tasks
```

### Source Code (planned implementation locations)

```text
pkg/config/
├── raw_stapel_image.go       # list-level os-pm cardinality validation
├── raw_packages_directive.go # existing per-entry conversion/validation
└── packages_directive_test.go or raw_stapel_image_test.go # co-located Ginkgo/Gomega tests
```

**Structure Decision**: Keep the change in the existing monolith CLI structure. The raw image conversion function owns the complete package list and already precedes command generation, so no new package or public API is needed.

## Phase 0: Research Summary

See [research.md](research.md). All technical-context questions are resolved: the existing parser conversion boundary is the appropriate validation point, no dependency choice is required, and no external integration contract is exposed.

## Phase 1: Design Summary

- [data-model.md](data-model.md) defines package directive fields, cardinality, and processing state.
- [contracts/config-validation.md](contracts/config-validation.md) defines the input rule, failure diagnostic, timing, and compatibility behavior.
- [quickstart.md](quickstart.md) defines focused and broad validation commands.

## Constitution Check — Post-Design

- **Simplicity**: PASS — a single O(n) count and early return.
- **Correctness/timing**: PASS — validation occurs before conversion completes and before `GeneratePackagesCommands` is called.
- **Compatibility**: PASS — zero/one `os-pm` and repeated non-`os-pm` directives remain valid; command-generation API is unchanged.
- **Testing**: PASS — test matrix covers all functional requirements and edge cases in the specification.
- **Operational gates**: PASS — no generated docs, dependencies, or CLI help text are changed.

No constitution violations require complexity tracking.

## Complexity Tracking

No violations.
