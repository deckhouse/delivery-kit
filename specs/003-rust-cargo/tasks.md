---
status: migrated
feature: rust-cargo
created: 2026-07-15
source: branch feat/sbom/get-rust-sbom
---

# Tasks: Rust Cargo Package Ecosystem

All tasks are completed — this feature was built incrementally on the branch and is now fully implemented.

## Task Group 1: Core Types and Ecosystem Registry

- [x] **T1.1** Add `PackagesDirectiveTypeRustCargo` constant
  - Files: `pkg/config/packages_directive.go`
  - Status: Constant added with canonical naming `rust-cargo`

- [x] **T1.2** Add `rust-cargo` entry to the `ecosystems` registry
  - Files: `pkg/config/packages_directive.go`
  - Status: Entry with `Cargo.toml`/`Cargo.lock` defaults, `cargo fetch` command, `rust-cargo-lock-cataloger` name

## Task Group 2: Config Parsing and Validation

- [x] **T2.1** Verify `rust-cargo` works with existing `fillFileBasedSpec` and ecosystem dispatch
  - Files: `pkg/config/packages_directive.go` (no changes needed)
  - Status: The existing generic `fillFileBasedSpec` handles the new type automatically via the registry

- [x] **T2.2** Verify validation for `rust-cargo`: missing `workdir` rejected, unknown type alias (`cargo`) rejected
  - Files: `pkg/config/packages_directive.go` (no changes needed)
  - Status: Existing `validate()` covers unknown types; `fillFileBasedSpec` enforces `workdir` presence

## Task Group 3: Command Generation

- [x] **T3.1** Verify `GeneratePackagesCommands` works with `rust-cargo` ecosystem entry
  - Files: `pkg/config/packages_commands.go` (no changes needed)
  - Status: Registry-based dispatch already handles new types — OSPM `if` branch, then generic `ecosystems[pkg.Type].InstallCmd` lookup

## Task Group 4: SBOM Integration

- [x] **T4.1** Verify `buildResolvers` and `ToCatalogers` work with `rust-cargo` ecosystem entry
  - Files: `pkg/sbom/managedinput/managedinput.go` (no changes needed)
  - Status: Dynamic, deterministic sorting by type name; `rust-cargo-lock-cataloger` maps correctly

- [x] **T4.2** Verify `FilterBOMBySourcePaths` works with rust-cargo-lock-cataloger paths (syft location keys)
  - Files: `pkg/sbom/managedinput/managedinput.go` (no changes needed)
  - Status: Prefix matching against `syft:location:*:path` properties works identically for all catalogers

## Task Group 5: Unit Tests

- [x] **T5.1** Write `packages_directive_rust_test.go` — unmarshal, defaults, error cases
  - Files: `pkg/config/packages_directive_rust_test.go`
  - Status: 4 entries covering default spec/lock, explicit overrides, missing workdir, alias rejection

- [x] **T5.2** Add rust-cargo entries to `GeneratePackagesCommands` table tests
  - Files: `pkg/build/stage/packages_test.go`
  - Status: 5 entries covering single entry, custom workdir, workdir with spaces, multiple entries, mixed types

- [x] **T5.3** Add rust-cargo `ToCatalogers` and `FilterBOMBySourcePaths` tests
  - Files: `pkg/sbom/managedinput/managedinput_test.go`
  - Status: 7 entries covering cataloger mapping for single/nested/multiple workdirs, exact-match path filtering (lock/spec), different workdir filtering, go-mod regression

## Task Group 6: E2E Tests

- [x] **T6.1** Create Cargo e2e test with fixture (`cargo_simple`)
  - Files: `test/e2e/sbom/cargo_test.go` + `_fixtures/inject/cargo_simple/`
  - Status: Validates `anyhow@1.0.86` in BOM after `cargo fetch`

## Task Group 7: Documentation

- [x] **T7.1** Update `docs/_data/werf_yaml.yml` with `rust-cargo` type description, defaults
  - Files: `docs/_data/werf_yaml.yml`
  - Status: `type`, `workdir`, `spec`, `lock` fields updated to include `rust-cargo`

- [x] **T7.2** Update English docs in `docs/pages_en/usage/build/stapel/instructions.md`
  - Files: `docs/pages_en/usage/build/stapel/instructions.md`
  - Status: Added rust-cargo section with description, example, and notes

- [x] **T7.3** Update Russian docs in `docs/pages_ru/usage/build/stapel/instructions.md`
  - Files: `docs/pages_ru/usage/build/stapel/instructions.md`
  - Status: Added rust-cargo section with description, example, and notes

## Gaps Identified

1. ⚠️ **E2E tests with native Buildah** — The e2e tests have `XEntry` (pending) for `native-chroot` and `native-rootless` container backends, indicating these aren't yet validated for Rust SBOM scenarios.