---
status: migrated
feature: lua-rock
created: 2026-07-16
source: branch feat/sbom/get-lua-sbom
---

# Tasks: Lua Rock Package Ecosystem

All tasks are completed — this feature was built incrementally on the branch and is now fully implemented.

## Task Group 1: Core Types and Ecosystem Registry

- [x] **T1.1** Add `PackagesDirectiveTypeLuaRock` constant
  - Files: `pkg/config/packages_directive.go`
  - Status: Constant added with canonical naming `lua-rock`

- [x] **T1.2** Add `lua-rock` entry to the `ecosystems` registry
  - Files: `pkg/config/packages_directive.go`
  - Status: Entry with no default spec (required), no default lock (rejected), `luarocks install --only-deps` command, `lua-rock-cataloger` name

## Task Group 2: Config Parsing and Validation

- [x] **T2.1** Verify `lua-rock` works with existing `fillFileBasedSpec` and ecosystem dispatch
  - Files: `pkg/config/packages_directive.go` (no changes needed)
  - Status: The existing generic `fillFileBasedSpec` handles the new type automatically. Empty `DefaultSpec` means `spec` is required; empty `DefaultLock` means `lock` is rejected.

- [x] **T2.2** Verify validation for `lua-rock`: missing `workdir` rejected, missing `spec` rejected, `lock` rejected, alias (`luarocks`) rejected
  - Files: `pkg/config/packages_directive.go` (no changes needed)
  - Status: Existing `validate()` covers unknown types and missing `workdir`; `fillFileBasedSpec` enforces `spec` presence and rejects `lock` when `DefaultLock` is empty

## Task Group 3: Command Generation

- [x] **T3.1** Verify `GeneratePackagesCommands` works with `lua-rock` ecosystem entry
  - Files: `pkg/config/packages_commands.go` (no changes needed)
  - Status: Registry-based dispatch already handles new types — OSPM `if` branch, then generic `ecosystems[pkg.Type].InstallCmd` lookup

## Task Group 4: SBOM Integration

- [x] **T4.1** Verify `buildResolvers` and `ToCatalogers` work with `lua-rock` ecosystem entry
  - Files: `pkg/sbom/managedinput/managedinput.go` (no changes needed)
  - Status: Dynamic, deterministic sorting by type name; `lua-rock-cataloger` maps correctly with only spec source path (no lock path)

- [x] **T4.2** Verify `FilterBOMBySourcePaths` works with `lua-rock-cataloger` paths
  - Files: `pkg/sbom/managedinput/managedinput.go` (no changes needed)
  - Status: Prefix matching against `syft:location:*:path` properties works identically for all catalogers; tests confirm rockspec path filtering

## Task Group 5: Unit Tests

- [x] **T5.1** Write `packages_directive_lua_test.go` — unmarshal, defaults, error cases
  - Files: `pkg/config/packages_directive_lua_test.go`
  - Status: 6 entries covering explicit spec, nested spec path, missing workdir, missing spec, lock rejection, alias rejection

- [x] **T5.2** Add lua-rock entries to `GeneratePackagesCommands` table tests
  - Files: `pkg/build/stage/packages_test.go`
  - Status: 4 entries covering single entry, workdir with spaces, multiple entries, mixed types (lua-rock + rust-cargo + os-pm)

- [x] **T5.3** Add lua-rock `ToCatalogers` and `FilterBOMBySourcePaths` tests
  - Files: `pkg/sbom/managedinput/managedinput_test.go`
  - Status: 2 entries covering rockspec path matching and go-mod regression alongside lua-rock cataloger

## Task Group 6: E2E Tests

- [x] **T6.1** Create Lua e2e test with fixture (`lua_simple`)
  - Files: `test/e2e/sbom/lua_test.go` + `_fixtures/inject/lua_simple/`
  - Status: Validates `werf-sbom-lua-app@0.1-1` in BOM after `luarocks install --only-deps`

- [x] **T6.2** Create negative e2e test (`lua_missing_rockspec`)
  - Files: `test/e2e/sbom/lua_test.go` + `_fixtures/negative/lua_missing_rockspec/`
  - Status: Validates build failure with "rockspec" or "luarocks" in error output when declared rockspec is missing

## Task Group 7: Documentation

- [x] **T7.1** Update `docs/_data/werf_yaml.yml` with `lua-rock` type description, defaults
  - Files: `docs/_data/werf_yaml.yml`
  - Status: `type`, `workdir`, `spec`, `lock` fields updated to include `lua-rock` with notes about required spec and no lock

- [x] **T7.2** Update English docs in `docs/pages_en/usage/build/stapel/instructions.md`
  - Files: `docs/pages_en/usage/build/stapel/instructions.md`
  - Status: Added lua-rock section with description, example, and notes about no default spec and no lock file

## Gaps Identified

1. ⚠️ **No determinism enforcement** — Unlike `go-mod` (go.sum), `python-uv` (`--frozen`), and `rust-cargo` (Cargo.lock), `lua-rock` has no lock file or `--frozen` equivalent. LuaRocks does not provide such a mechanism. This is analogous to `python-pip`. Users must pin exact versions in their `.rockspec` file for reproducible builds.

2. ⚠️ **E2E tests with native Buildah** — The e2e tests have `XEntry` (pending) for `native-chroot` and `native-rootless` container backends, indicating these aren't yet validated for Lua SBOM scenarios. This is consistent with all other ecosystem types.
