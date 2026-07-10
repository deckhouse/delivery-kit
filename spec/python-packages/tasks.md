---
status: migrated
feature: python-packages
created: 2026-07-10
source: branch feat-sbom-get-python-sbom
---

# Tasks: Python Package Ecosystems

All tasks are completed — this feature was built incrementally on the branch and is now fully implemented.

## Task Group 1: Core Types and Ecosystem Registry

- [x] **T1.1** Add `PythonPackageEcosystem` types: `PackagesDirectiveTypePythonUV`, `PackagesDirectiveTypePythonPip`, `PackagesDirectiveTypePythonPoetry`
  - Files: `pkg/config/packages_directive.go`
  - Status: Constants added with canonical naming `python-{uv,pip,poetry}`

- [x] **T1.2** Rename `GoModSpec` to `FileBasedSpec` and update all references
  - Files: `pkg/config/packages_directive.go` + all callers
  - Status: Struct used for Go-mod and all Python ecosystems

- [x] **T1.3** Implement `PackageEcosystem` struct and `ecosystems` map registry
  - Files: `pkg/config/packages_directive.go`
  - Status: Registry with Type, Aliases, DefaultSpec, DefaultLock, InstallCmd, CatalogerName

- [x] **T1.4** Implement alias resolution (`aliasToType` index) and `Ecosystems()` accessor
  - Files: `pkg/config/packages_directive.go`
  - Status: Aliases `uv/pip/poetry` canonicalized at parse time

## Task Group 2: Config Parsing and Validation

- [x] **T2.1** Refactor `rawPackagesDirective.toDirective()` with alias resolution and ecosystem dispatch
  - Files: `pkg/config/raw_packages_directive.go`
  - Status: OSPM handled via `if`; file-based types delegated to `fillFileBasedSpec`

- [x] **T2.2** Implement `fillFileBasedSpec` (replaces `fillGoModSpec`)
  - Files: `pkg/config/raw_packages_directive.go`
  - Status: Reads defaults from ecosystem registry; validates spec type (must be string); rejects lock for lockless ecosystems (pip)

- [x] **T2.3** Update `PackagesDirective.validate()` for ecosystem-based validation
  - Files: `pkg/config/packages_directive.go`
  - Status: OSPM checks packages non-empty; file-based checks workdir non-empty; unknown types rejected

## Task Group 3: Command Generation

- [x] **T3.1** Refactor `GeneratePackagesCommands` to use ecosystem registry
  - Files: `pkg/config/packages_commands.go`
  - Status: OSPM has dedicated `if`; other types dispatch via `ecosystems[pkg.Type].InstallCmd`

- [x] **T3.2** Add Python install commands with `--frozen` determinism for uv and `--no-root` for poetry
  - Files: `pkg/config/packages_directive.go` (ecosystem entries)
  - Status: `uv sync --frozen`, `pip install --no-cache-dir -r <spec>`, `poetry install --no-root`

## Task Group 4: SBOM Integration

- [x] **T4.1** Refactor `buildResolvers` to construct cataloger resolvers from `config.Ecosystems()`
  - Files: `pkg/sbom/managedinput/managedinput.go`
  - Status: Dynamic, deterministic sorting by type name

- [x] **T4.2** Update `ToCatalogers` to handle python-package-cataloger
  - Files: `pkg/sbom/managedinput/managedinput.go`
  - Status: Python directives map to `python-package-cataloger` with correct source paths (spec + lock when available)

- [x] **T4.3** Ensure `FilterBOMBySourcePaths` works with python property paths (syft location keys)
  - Files: `pkg/sbom/managedinput/managedinput.go`
  - Status: Uses prefix matching against `syft:location:*:path` properties; works identically for go and python components

## Task Group 5: Unit Tests

- [x] **T5.1** Extract `directivesFromYaml` shared test helper
  - Files: `pkg/config/helpers_test.go`
  - Status: Shared between go-mod and python test files

- [x] **T5.2** Write `packages_directive_python_test.go` — unmarshal, defaults, aliases, error cases
  - Files: `pkg/config/packages_directive_python_test.go`
  - Status: 14 entries covering all types, aliases, explicit overrides, missing workdir, invalid spec type, unknown type, lock rejection for pip

- [x] **T5.3** Refactor `packages_directive_go_mod_test.go` to use `FileBasedSpec` and shared helper
  - Files: `pkg/config/packages_directive_go_mod_test.go`
  - Status: All existing tests pass with new struct

- [x] **T5.4** Refactor `raw_packages_directive_test.go` to use DescribeTable for normalizePackages
  - Files: `pkg/config/raw_packages_directive_test.go`
  - Status: 6 entries replacing individual It blocks; python smoke test added

- [x] **T5.5** Add python-specific `ToCatalogers` and `FilterBOMBySourcePaths` tests
  - Files: `pkg/sbom/managedinput/managedinput_test.go`
  - Status: 5 entries testing python-package-cataloger mapping, pip lockless, uv+poetry lock paths, path filtering, go-mod regression

- [x] **T5.6** Add `buildResolvers` determinism test
  - Files: `pkg/sbom/managedinput/managedinput_test.go`
  - Status: Verifies deterministic ordering across 20 invocations and alphabetical sort

## Task Group 6: E2E Tests

- [x] **T6.1** Create pip e2e test with fixture (`pip_simple`)
  - Files: `test/e2e/sbom/pip_test.go` + `_fixtures/inject/pip_simple/`
  - Status: Validates `requests@2.32.3` in BOM after `pip install -r requirements.txt`

- [x] **T6.2** Create poetry e2e test with fixture (`poetry_simple`)
  - Files: `test/e2e/sbom/poetry_test.go` + `_fixtures/inject/poetry_simple/`
  - Status: Validates `requests@2.32.3` in BOM after `poetry install --no-root`

- [x] **T6.3** Create uv e2e test with fixture (`uv_simple`)
  - Files: `test/e2e/sbom/uv_test.go` + `_fixtures/inject/uv_simple/`
  - Status: Validates `requests@2.32.3` in BOM after `uv sync --frozen`

## Task Group 7: Documentation

- [x] **T7.1** Update `docs/_data/werf_yaml.yml` with Python type descriptions, aliases, defaults
  - Files: `docs/_data/werf_yaml.yml`
  - Status: `type`, `workdir`, `spec`, `lock` fields updated for all three Python ecosystems

## Task Group 8: Incidental Cleanup (extracted from PR)

- [x] **T8.1** Remove `serviceLabelsConfigMutation` from `verity_annotation.go` and simplify `SignStage.MutateImage`
  - Files: `pkg/build/stage/verity_annotation.go`, `pkg/build/stage/sign.go`
  - Status: Service labels propagation moved into the registry mutation flow

- [x] **T8.2** Clean up `mutateImage` in docker_registry (remove stale cf snapshot logic)
  - Files: `pkg/docker_registry/api/mutate.go`
  - Status: Removed `cfBeforeLayerMutation` read that was no longer needed

- [x] **T8.3** Delete obsolete mutate tests
  - Files: `pkg/docker_registry/api/mutate_test.go`, `pkg/docker_registry/api/suite_test.go`
  - Status: Tests removed as they tested removed behavior

## Gaps Identified

1. ⚠️ **poetry lock enforcement** — Unlike `uv --frozen`, poetry's `install --no-root` doesn't have a built-in flag to reject a missing or outdated `poetry.lock`. The lock file existence is expected but not enforced at the package manager level.
2. ⚠️ **E2E tests with native Buildah** — The e2e tests have `XEntry` (pending) for `native-chroot` and `native-rootless` container backends, indicating these aren't yet validated for Python SBOM scenarios.