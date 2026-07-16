# Tasks: Enforce os-pm Determinism via Spec+Lock Files

**Input**: Migrated from commit `714fe86b6` on branch `feat/config/enforce-pm-determinism`.

**Prerequisites**: None — all tasks are completed.

## Phase 1: Config Layer — Remove Flat Package Model

- [x] T001 Remove `PackagesSpec` struct from `pkg/config/packages_directive.go`
- [x] T002 Remove `normalizePackages()` function from `pkg/config/packages_directive.go`
- [x] T003 Add `os-pm` entry to the `ecosystems` registry in `pkg/config/packages_directive.go` with `DefaultSpec: "pm.yaml"`, `DefaultLock: "pm.lock"`, install command `pm sync --from <workdir>/pm.lock`
- [x] T004 Unify `validate()` for all package types in `pkg/config/packages_directive.go` — require `workdir` and `spec` for all types including `os-pm`

## Phase 2: YAML Parsing — Unify to File-Based Spec

- [x] T005 Remove `fillOSPMSpec()` from `pkg/config/raw_packages_directive.go`; route all types through `fillFileBasedSpec()`
- [x] T006 Change `rawPackagesDirective.Spec` type from `interface{}` to `string` in `pkg/config/raw_packages_directive.go`
- [x] T007 Update `fillFileBasedSpec()` to handle `Spec` and `Lock` overrides with defaults from the registry
- [x] T008 Remove `os-pm`-specific validation in `UnmarshalYAML` (old: "spec is required for os-pm")

## Phase 3: Command Generation — Uniform Dispatch

- [x] T009 Refactor `GeneratePackagesCommands()` in `pkg/config/packages_commands.go` to dispatch all ecosystem types through the registry, keeping only the snapshot command special-case for `os-pm`

## Phase 4: Build Integration — Lock Path Propagation

- [x] T010 Add `OSPMLockPath()` method to `StapelImageBase` in `pkg/config/stapel_image_base.go` (returns `<workdir>/<lock>`)
- [x] T011 Change `convergeImageSbom()` in `pkg/build/build_phase.go` from `hasOsPmPackages bool` to `osPmLockPath string`
- [x] T012 Update `ConvergeWithMerge()` in `pkg/build/sbom_step.go` to pass `osPmLockPath` to `osPm.CollectBOM()`

## Phase 5: SBOM Collection — Lock File Instead of Runtime Query

- [x] T013 Rename `ParsePmInstalledJSON()` → `ParsePmLockJSON()` in `pkg/sbom/packages/os_pm/os_pm.go`; update to parse `{"metadata":..., "packages":{...}}` envelope format
- [x] T014 Update `collectPacketsFromLock()` in `pkg/sbom/packages/os_pm/collect.go` to read `pm.lock` from inside the container instead of running `pm info --installed --json`
- [x] T015 Update `CollectBOM()` to accept `lockPath` parameter

## Phase 6: Tests — Unit and E2E Updates

- [x] T016 Update `pkg/build/stage/packages_test.go` — change test expectations from `pm install <pkg>` commands to `pm sync --from <lock>` commands
- [x] T017 Update `pkg/config/raw_packages_directive_test.go` — remove old `normalizePackages` tests, add new default spec/lock tests, remove old `spec: [strings]` test cases
- [x] T018 Update `pkg/config/helpers_test.go` — return error instead of `Expect` for cleaner test setup
- [x] T019 Update `pkg/sbom/packages/os_pm/os_pm_test.go` — rename test references from `ParsePmInstalledJSON` to `ParsePmLockJSON`, update empty-map test input
- [x] T020 Update `pkg/sbom/packages/os_pm/testdata/pm_info_installed.json` — add `metadata` + `packages` envelope
- [x] T021 Add `pm.lock` and `pm.yaml` files to all e2e fixture directories (`test/e2e/sbom/_fixtures/`)
- [x] T022 Update `test/e2e/sbom/packages_test.go` — update hash expectations, error message assertions, container factory version
- [x] T023 Update `test/e2e/sbom/lifecycle_test.go` — update hash expectations

## Phase 7: E2E Fixtures (new)

- [x] T024 Add `cargo_alias` e2e fixture for Rust/Cargo with alias support
