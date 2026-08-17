# Research: Inline os-pm Syntax (reverting 015)

**Date**: 2026-08-13 | **Branch**: `017-inline-os-pm-syntax-again`

## 1. Config Parsing Architecture

### Decision: Restore inline `spec` list parsing for `os-pm`

The current `rawPackagesDirective` stores `Spec` as `interface{}` — this was used in 009 to hold both `string` (file path for non-os-pm types) and `[]interface{}` (package list for os-pm). The 015 change forced `os-pm` through `FileBasedSpec` by setting default file paths via `fillFileBasedSpec`. For 017, `fillFileBasedSpec` must skip `os-pm` entirely, and `toDirective` must convert `spec` from `[]interface{}` to `[]string` when `type == "os-pm"`.

- **Rationale**: The `interface{}` field already exists and supports both formats. No structural changes needed to `rawPackagesDirective` — only the `toDirective` code path needs to branch on type.
- **Alternatives considered**:
  - Adding a separate field `SpecList []string` — rejected as it adds unnecessary struct bloat.
  - Using a separate directive type for os-pm — rejected, excessive abstraction.

### Decision: Delete `PMBOMPatcher` and restore `CollectBOM`

The 015 `PMBOMPatcher` (in `pkg/sbom/packages/os_pm/pm_bom_patcher.go`) reads `pm.lock` from the git commit and creates a CycloneDX BOM. For 017, this is replaced by `CollectBOM` which reads `/var/lib/pm/index.json` from inside the built image via `ReadFileFromImage`.

- **Rationale**: Reading the final package state from the image is more accurate than reading a lock file from the build context, especially when multiple os-pm sections are involved. The `ParsePmInstalledJSON` function already parses the flat JSON format produced by `pm` at `/var/lib/pm/index.json`.
- **Alternatives considered**: Keeping `PMBOMPatcher` and adding `CollectBOM` alongside — rejected because having two sources of truth for os-pm components would cause duplication or conflict.
- **Implementation detail**: The `pm_bom_patcher.go` file and its test file will be deleted. `collect.go` will be restored from the 009-era logic (reading `/var/lib/pm/index.json` via `ReadFileFromImage`).

## 2. Command Generation

### Decision: New `formatInstallCommand` for `os-pm`

The `os-pm` ecosystem's `InstallCmd` will change from `pm sync --from <lockfile>` to `pm install <pkg1> <pkg2> ...`. The `InstallCmd` callback signature must change to accept the package name list.

- **Rationale**: The `pm install` command accepts multiple package arguments directly — this matches the inline syntax. The preamble (mkdir, version file write, env vars) is preserved from 009/012.
- **Current `InstallCmd` signature**: `func(workdir, specFile, lockFile string, env map[string]string) string`
- **New signature for `os-pm`**: `func(workdir string, pkgs []string, env map[string]string) string`
- **Alternatives considered**: Changing the generic `InstallCmd` signature for all ecosystems — rejected because only `os-pm` uses inline lists. The callback type should remain generic; ecosystems that don't need the new parameter can ignore it.

### Decision: `PackageEcosystem.InstallCmd` signature change

The `InstallCmd` field type in `PackageEcosystem` will change from `func(workdir, specFile, lockFile string, env map[string]string) string` to `func(workdir string, files FileBasedSpec, pkgs []string, env map[string]string) string` to support both file-based and package-list ecosystems.

- **Rationale**: This preserves backward compatibility for non-os-pm ecosystems while allowing os-pm to receive the package list.
- **Impact**: All `InstallCmd` implementations across all ecosystems must update their signatures. Non-os-pm callbacks will simply ignore the `pkgs` parameter.

## 3. SBOM Collection Pipeline

### Decision: Keep runtime os-pm collection inside `pkg/sbom/packages/os_pm`

The SBOM collection flow changes from:

```
PMBOMPatcher (reads pm.lock from git) → syft scan → GOST upsert
```

To:

```
syft scan (os-pm cataloger skipped) → os_pm package operation (reads /var/lib/pm/index.json and integrates it) → generic patchers → GOST upsert
```

- **Rationale**: `CollectBOM` reads the actual final state from the image, which naturally merges packages from multiple os-pm sections.
- **Implementation detail**: The `pkg/sbom/packages/os_pm` operation owns reading `/var/lib/pm/index.json`, merging its components/dependencies, and ensuring the resulting BOM is ready before generic external-reference patchers run. `pkg/build/sbom_step.go` only coordinates the package-level operation and must not duplicate os-pm merge logic.
- **Cache implication**: The stable checksum must not include a separate `osPmEnabled` flag. Verify that equivalent generic SBOM inputs produce the same checksum and that runtime-index changes remain tied to the image identity/cache lookup rather than a build-layer boolean.
- **Fixture implication**: E2E expectations must be based on components guaranteed by the fixture. Confirm whether `openssl` is present in the trusted builder base image; if not, declare it explicitly rather than relying on an incidental base-image package.

### Decision: Restore `HasOSPMPackages()` boolean

Replace `OSPMLockPath() string` and `OSPMSpecPath() string` on `StapelImageBase` with `HasOSPMPackages() bool`. The build phase checks this boolean instead of comparing string paths to `""`.

- **Rationale**: The presence of os-pm packages is no longer determined by the existence of a lock file path. A simple boolean is cleaner.
- **Alternatives considered**: Keeping `OSPMLockPath` and returning `""` for no-file — rejected as misleading when there's no lock file at all.

## 4. Ecosystems Configuration

### Decision: Update `os-pm` ecosystem entry and move SBOM metadata to `pkg/sbom`

| Field | Current (015) | New (017) |
|-------|---------------|-----------|
| `DefaultSpecFile` | `"pm.yaml"` | `""` |
| `DefaultLockFile` | `"pm.lock"` | `""` |
| `CatalogerName` | `"os-pm-lock-cataloger"` | `os_pm.CatalogerName` (the value is defined once in `pkg/sbom/packages/os_pm`) |
| `InstallCmd` | `pm sync --from <lockfile>` | `pm install <pkgs>` |

- **Rationale**: Inline syntax has no default spec/lock file. The cataloger name is updated to reflect the runtime-index source. The install command switches to argument-based invocation.
- **Implementation detail**: Keep the cataloger-name constant in `pkg/sbom/packages/os_pm`, and set `PackageEcosystem.CatalogerName` to that exported value from `pkg/config/packages_directive.go`, matching language ecosystem registration. Add a config test that asserts the os-pm ecosystem exposes the same name. Keep `ContainerFactoryIndexPath` and the version-file path in the SBOM package and reuse them from command generation; no caller redeclares the path strings.

## 5. Configuration Validation

### Decision: Restore validation for inline spec list

- `spec` for `os-pm` must be a non-empty list of strings → reject empty lists
- `spec` for `os-pm` must not be a string → reject file path strings (SC-009)
- `workdir` for `os-pm` must not be specified → reject with validation error (SC-003)
- `env` for `os-pm` continues to work as before (FR-005)

## 6. `containerFactoryVersion` Resolution

### Decision: Read persisted container-factory version from the image only

The `containerFactoryVersion` PURL qualifier is read only from `ContainerFactoryVersionPath` (`/var/lib/pm/container-factory-version`) inside the built image. `PACKAGES_VERSION` is available to the shell command inside the container and is persisted there by the command preamble; it is not a valid SBOM collector input from the host process.

The runtime index path and version-file path are owned exclusively by `pkg/sbom/packages/os_pm`. Command generation imports and reuses these exported constants; `pkg/config/packages_commands.go` contains no duplicate PM path values.

- **Rationale**: The SBOM collector runs outside the built image, while `PACKAGES_VERSION` is scoped to the package command inside the container. The persisted file is the only authoritative and reproducible source available during SBOM collection.
- **Implementation detail**: `ReadContainerFactoryVersion` reads `ContainerFactoryVersionPath` from the image. Remove `readContainerFactoryVersionFromEnv`; `CollectBOM` uses the image file directly.

## 7. Test Data Migration

### Decision: Update all unit tests from file-based to inline syntax

All test files modified in 015 for file-based syntax must be reverted to inline syntax:

- `pkg/config/raw_packages_directive_test.go` — change `"spec": "pm.yaml"` to `"spec": ["curl", "jq"]` for os-pm entries; invert the "os-pm with list spec is rejected" test to assert acceptance
- `pkg/config/packages_directive_javascript_test.go` — update os-pm entries in combined config tests
- `pkg/config/packages_commands_test.go` — assert `pm install curl jq` instead of `pm sync --from pm.lock`, and assert generated PM commands use the SBOM-owned path constants
- `pkg/config/stapel_image_base_test.go` — test `HasOSPMPackages()` instead of `OSPMLockPath()`
- `pkg/build/stage/packages_test.go` — update os-pm entries
- `pkg/config/packages_directive_test.go` or the existing ecosystem test — assert the os-pm `CatalogerName` equals `os_pm.CatalogerName`

### Decision: Update e2e fixtures

All e2e test fixtures under `test/e2e/sbom/_fixtures/` that use `pm.yaml`/`pm.lock` must be updated to inline `spec` lists. The `pm.yaml` and `pm.lock` files must be deleted.

## 8. Key Architectural Decisions

### ADR-1: Inline spec list is the ONLY format for os-pm

The file-based `spec: "pm.yaml"` syntax that was introduced in 015 and supported by 006 is **removed entirely** for `os-pm`. Users must declare packages inline. Other package types (e.g., `go-mod`) continue to use file-based spec.

### ADR-2: Multiple os-pm sections → multiple independent pm commands

Each `os-pm` section in `packages` generates one `pm install <pkgs>` command. All commands are executed in sequence during the build stage. The SBOM is produced from the single combined state in `/var/lib/pm/index.json` after all commands have run.

### ADR-3: No workdir for os-pm

The `workdir` field is not applicable to OS-level package managers. Specifying `workdir` on an `os-pm` directive produces a config validation error (not a warning). This is enforced at config parse time in `validate()`.

### ADR-4: SBOM source is the built image, not the build context

All os-pm package data for SBOM comes from `/var/lib/pm/index.json` inside the built image. No os-pm package data is read from files in the build context (e.g., `pm.lock`). This ensures accuracy even with multiple os-pm sections.

### ADR-5: `env` support per os-pm section

Each `os-pm` section can have its own `env` block. Environment variables are passed as inline shell prefixes to the `pm install` command. This is unchanged from 012 behavior.