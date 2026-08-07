# Research: os-pm File-Based Syntax

## Unknown 1: Builder Interface & HasOSPMPackages() → OSPMLockPath()

### Current State

**`HasOSPMPackages()`** is defined in `pkg/config/stapel_image_base.go`:

```go
func (c *StapelImageBase) HasOSPMPackages() bool {
    for _, p := range c.Packages {
        if p.Type == PackagesDirectiveTypeOSPM {
            return true
        }
    }
    return false
}
```

This method is used in the build pipeline to determine whether the image needs the os-pm packages stage (e.g., for generating SBOM catalogers or triggering package install). The spec requires changing this to `OSPMLockPath()` returning the lock file path (relative to repository root, e.g., `pm.lock`).

### Build Pipeline Integration

The packages commands flow through the build pipeline as follows:

1. **Config parsing** (`pkg/config/raw_stapel_image.go:320-336`): During `toStapelImageDirective()`, each `rawPackagesDirective` is converted via `rawPkg.toDirective(i)` and appended to `imageBase.Packages`.

2. **Command generation** (same file, lines 329-336): When SBOM is enabled and there are packages, `GeneratePackagesCommands(imageBase.Packages)` is called. The result is injected into `imageBase.Shell.Packages`:

   ```go
   if len(imageBase.Packages) > 0 && meta.Build.Sbom != nil && meta.Build.Sbom.Enable {
       packagesCommands := GeneratePackagesCommands(imageBase.Packages)
       if len(packagesCommands) > 0 {
           if imageBase.Shell == nil {
               imageBase.Shell = &Shell{}
           }
           imageBase.Shell.Packages = packagesCommands
       }
   }
   ```

3. **Shell builder** (`pkg/build/builder/shell.go`): `IsPackagesEmpty()` checks if there are shell commands for "Packages" stage. `Packages()` runs those commands.

4. **PackagesStage** (`pkg/build/stage/packages.go`): Calls `s.builder.IsPackagesEmpty()` and `s.builder.Packages()` — these map to Shell builder methods, which execute the commands stored in Shell.Packages.

**Conclusion**: The ecosystem packages commands (from `GeneratePackagesCommands()`) are injected into the Shell builder's Packages stage as regular shell commands. Once `os-pm` is registered with the proper `InstallCmd`, the generated commands will automatically flow through this same path. No changes needed in the Shell builder or PackagesStage — the wiring is generic.

### Decision

- **Change**: `HasOSPMPackages()` → `OSPMLockPath()` returning the lock file path (e.g., `pm.lock`) for the first `os-pm` directive, or empty string if no `os-pm` packages.
- **Rationale**: The lock file path is needed by the build phase for SBOM and other purposes. A simple boolean is insufficient when custom `lock` paths can be specified.
- **Alternatives considered**: Keep `HasOSPMPackages()` and add `OSPMLockPath()` separately — rejected because the boolean is not independently useful.

## Unknown 2: Test Fixture Locations

### Current Test Files Referencing Inline `os-pm` Syntax

1. **`pkg/config/raw_packages_directive_test.go`** — Tests for unmarshal/validation of inline `os-pm`:
   - `"os-pm with inline spec list"` — `spec: [curl, jq]` → `PackagesSpec{Packages: []string{"curl", "jq"}}`
   - `"os-pm with single package in spec"` — `spec: [curl]` → `PackagesSpec{Packages: []string{"curl"}}`
   - `"os-pm without packages"` — empty spec → expects error
   - Various env var tests with inline `spec: [curl]`

2. **`pkg/config/packages_directive_javascript_test.go`** — Combined config tests:
   - Entries `"go-mod + javascript-npm + os-pm combined config parses correctly"` and `"go-mod + rust-cargo + javascript-yarn + os-pm combined config"` — test inline `os-pm` syntax alongside other types

3. **`pkg/config/packages_commands_test.go`** — Command generation tests:
   - `"GeneratePackagesCommands os-pm"` block — tests `pm install curl` style commands
   - `"GeneratePackagesCommands non-os-pm backward compatible"` block — validates other types
   - Various env var test blocks with inline `os-pm` syntax

4. **`pkg/config/packages_directive_python_test.go`**, **`pkg/config/packages_directive_rust_test.go`**, **`pkg/config/packages_directive_go_mod_test.go`**, **`pkg/config/packages_directive_lua_test.go`** — may not reference os-pm directly but reference `PackagesSpec` or `Spec.Packages` in assertions

5. **`pkg/sbom/managedinput/managedinput_test.go`** — SBOM cataloger resolution tests

6. **`pkg/build/stage/packages_test.go`** — Packages stage test, references `GeneratePackagesCommands`

### E2E Test Fixtures

FR-016 explicitly lists the following fixture groups as requiring migration to file-based `pm.yaml`/`pm.lock`:

- `test/e2e/sbom/_fixtures/stage_deps/` (states 0–2)
- `test/e2e/sbom/_fixtures/stage_deps_file/` (states 0–1)
- `test/e2e/sbom/_fixtures/type_change/` (state0)

Additionally, SC-013 requires ALL e2e fixtures referencing inline `os-pm` syntax to be migrated. The full list:

| Fixture | File |
|---------|------|
| `inject/ospm_basic` | `test/e2e/sbom/_fixtures/inject/ospm_basic/werf.yaml` |
| `inject/ospm_gost_override` | `test/e2e/sbom/_fixtures/inject/ospm_gost_override/werf.yaml` |
| `inject/ospm_scratch_secrets` | `test/e2e/sbom/_fixtures/inject/ospm_scratch_secrets/werf.yaml` |
| `stage_deps_file/state0` | `test/e2e/sbom/_fixtures/stage_deps_file/state0/werf.yaml` |
| `stage_deps_file/state1` | `test/e2e/sbom/_fixtures/stage_deps_file/state1/werf.yaml` |
| `stage_deps/state0..state2` | `test/e2e/sbom/_fixtures/stage_deps/state*/werf.yaml` |
| `packages_merge/base_with_child` | `test/e2e/sbom/_fixtures/packages_merge/base_with_child/werf.yaml` |
| `packages_merge/parent_propagation` | `test/e2e/sbom/_fixtures/packages_merge/parent_propagation/werf.yaml` |
| `type_change/state0` | `test/e2e/sbom/_fixtures/type_change/state0/werf.yaml` |
| `lifecycle/multi_image` | `test/e2e/sbom/_fixtures/lifecycle/multi_image/werf.yaml` |
| `purl_resolver_errors` | `test/e2e/sbom/_fixtures/purl_resolver_errors/werf.yaml` |
| `negative/broken_pm` | `test/e2e/sbom/_fixtures/negative/broken_pm/werf.yaml` |
| `negative/no_pm_binary` | `test/e2e/sbom/_fixtures/negative/no_pm_binary/werf.yaml` |
| `regressions/manifest_annotation` | `test/e2e/sbom/_fixtures/regressions/manifest_annotation/werf.yaml` |

### E2E Go Test Files

The following e2e test `.go` files reference inline `os-pm` assertions and command expectations:

- `test/e2e/sbom/packages_test.go` — `pm install` command assertions, `spec:` in test descriptions
- `test/e2e/sbom/gost_test.go` — os-pm GOST override tests
- `test/e2e/sbom/lifecycle_test.go` — lifecycle tests referencing os-pm packages
- `test/e2e/sbom/stage_dependencies_test.go` — `stage_deps_file` test, type-change test with os-pm

### Migration Approach for E2E Fixtures

For each fixture:
1. The `spec: [pkg==ver]` inline list must be removed from `werf.yaml`
2. A `pm.yaml` file must be added alongside `werf.yaml` containing the same package list in pm format (see [pm.yaml format](#pm.yaml-format))
3. Generate `pm.lock` by running `pm lock --from=pm.yaml` in the fixture directory (requires `pm` installed locally)
4. The `git.stageDependencies.packages` (if present) must track `pm.yaml` and/or `pm.lock` instead of the old file

The `stage_deps_file` e2e test (SC-014) must demonstrate that changes to `pm.yaml` or `pm.lock` trigger SBOM regeneration via `git.stageDependencies.packages`.

### Decision

- All test files referencing inline `os-pm` syntax must be updated to use file-based syntax (`spec: "pm.yaml"`).
- `PackagesSpec` assertions (`Expect(packages[i].Spec.Packages).To(...)`) must change to `FileBased` assertions.
- `pm install` command assertions must change to `pm sync --from pm.lock` assertions.
- Special-cased `packages[i].Type == PackagesDirectiveTypeOSPM` branches in test assertions must be removed.
- 16 e2e fixture `werf.yaml` files must be migrated to file-based syntax with accompanying `pm.yaml` and `pm.lock` files.
- E2e Go test files must update command expectations from `pm install` to `pm sync --from pm.lock`.

## Unknown 3: Git Stage Dependencies Behavior

### Current State

The `stageDependencies.packages` mechanism is part of the `git` mapping in `werf.yaml`. When files listed in `git.stageDependencies.packages` change, the packages stage checksum is invalidated and the stage is re-executed. This is implemented in:

- `pkg/build/stage/packages.go` — `GetDependencies()` calls `s.getStageDependenciesChecksum(ctx, c, Packages)` to compute checksum from git stage dependencies.

The mechanism is generic and works for all package types. No `os-pm`-specific exclusion exists. Once `pm.yaml` and `pm.lock` are files in the repository that are tracked by `git.stageDependencies.packages`, changes to them will correctly trigger packages stage re-execution.

### Decision

No code changes needed — the mechanism already works for all file-based package types. The user configures `git.stageDependencies.packages` to track `pm.yaml` and `pm.lock` as needed.

## Unknown 4: Build Phase Command Wiring

### Dead Code from Updated Spec

Per updated FR-002 and FR-010b:

1. **`pkg/config/packages_commands.go`**:
   - `ContainerFactoryVersionDir`, `ContainerFactoryVersionFile` constants — **KEPT** (FR-002 requires container factory version file for SBOM purl qualifier)
   - `ContainerFactoryVersionIndexFile` constant — **DEAD** (only used by runtime index reader)
   - `formatMkdirCommand()`, `formatVersionFileCommand()` functions — **KEPT** (FR-002 requires them to write `ContainerFactoryVersionFile` during build)
   - Keep also: `formatEnvVars()`, `formatSecretVar()`, `formatSyncCommand()`, `GeneratePackagesCommands()`

2. **`pkg/sbom/packages/os_pm/`** — **Partially dead**:
   - `collect.go`: `collectInstalledPackets()` — **DEAD** (reads runtime index from inside image, per FR-010b no package data from inside built image)
   - `collect.go`: `readContainerFactoryVersion()` — **KEPT** (reads `ContainerFactoryVersionFile` for purl qualifier, per FR-010b)
   - `collect.go`: `CollectBOM()` — needs rework to remove `collectInstalledPackets()` call
   - `os_pm.go`: `ParsePmLock()` — **NOT DEAD** (per FR-017 and spec clarification: reused to read `pm.lock` from build context — `pm.lock` has same format as `/var/lib/pm/index.json`)
   - `os_pm.go`: `collectPacketsFromLock()` — **NOT DEAD** (reused for `pm.lock` per FR-017)
   - `os_pm.go`: `ConvertToCycloneDX()`, `PmPackageInfo`, helper functions — may still be needed for pm.lock-to-CycloneDX conversion; needs evaluation
   - Tests: testdata and test code for dead functions needs cleanup

3. SBOM for `os-pm` packages (names, versions, dependencies) is now handled by build-context scanning via `managedinput.go`. The container factory version is still read from inside the image for the purl qualifier.

### Current Flow (after implementation)

1. **Config parsing**: `raw_stapel_image.go` calls `GeneratePackagesCommands(imageBase.Packages)` and injects results into `imageBase.Shell.Packages`
2. **Shell builder**: `Packages()` method runs the commands stored in `Shell.Packages`
3. **PackagesStage**: Orchestrates the stage lifecycle (dependencies, prepare image)
4. **SBOM**: `managedinput.ToCatalogers()` derives catalogers from `config.Ecosystems()` — `os-pm` automatically gets a cataloger with name `"os-pm-lock-cataloger"` and source paths `["pm.yaml", "pm.lock"]`
5. **Container factory version**: still read from inside the built image via `readContainerFactoryVersion()` for purl qualifier
6. **No runtime package index**: all component data comes from `pm.lock` scanning in the build context

### How `os-pm` Commands Are Generated

Currently in `packages_directive.go`:
```go
PackagesDirectiveTypeOSPM: {
    Type: PackagesDirectiveTypeOSPM,
    InstallCmd: func(_, _ string, specList []string, env map[string]string) string {
        return fmt.Sprintf("%s; %s; %s", formatMkdirCommand(), formatVersionFileCommand(), formatInstallCommand(specList, env))
    },
},
```

Where `formatInstallCommand` generates:
```bash
mkdir -p /var/lib/pm
PACKAGES_VERSION="${PACKAGES_VERSION:-$(cat /run/secrets/PACKAGES_VERSION 2>/dev/null || true)}" ... && printf '%s\n' "$PACKAGES_VERSION" > /var/lib/pm/container-factory-version
PACKAGES_VERSION="${PACKAGES_VERSION:-$(cat /run/secrets/PACKAGES_VERSION 2>/dev/null || true)}" ... pm install curl jq
```

### Target State

The new `InstallCmd` for `os-pm` should generate:
```bash
mkdir -p /var/lib/pm
PACKAGES_VERSION="${PACKAGES_VERSION:-$(cat /run/secrets/PACKAGES_VERSION 2>/dev/null || true)}" && printf '%s\n' "$PACKAGES_VERSION" > /var/lib/pm/container-factory-version
PACKAGES_VERSION="${PACKAGES_VERSION:-$(cat /run/secrets/PACKAGES_VERSION 2>/dev/null || true)}" REGISTRY="${REGISTRY:-$(cat /run/secrets/REGISTRY 2>/dev/null || true)}" pm sync --from pm.lock
```

If environment variables are specified, they are prepended:
```bash
MY_ENV="value" PACKAGES_VERSION="${PACKAGES_VERSION:-$(cat ...)}" printf '%s\n' "$PACKAGES_VERSION" > /var/lib/pm/container-factory-version ; PACKAGES_VERSION="${PACKAGES_VERSION:-$(cat ...)}" REGISTRY="${REGISTRY:-$(cat ...)}" pm sync --from pm.lock
```

Key changes from current:
- Replace `pm install <pkgs>` with `pm sync --from <lockfile>` (uses `formatSyncCommand` instead of `formatInstallCommand`)
- No `cd <workdir>` prefix (os-pm is always at repo root)
- **Container factory version file write is PRESERVED** (per FR-002, writes `ContainerFactoryVersionFile` for SBOM purl qualifier)
- **Runtime index (`ContainerFactoryVersionIndexFile`) is NOT written** — package data comes from `pm.lock` in build context

### Decision

The `InstallCmd` function signature `func(workdir, specFile string, specList []string, env map[string]string) string` generates a command for `os-pm`: the container factory version preamble (`formatMkdirCommand`, `formatVersionFileCommand`) is INCLUDED before `pm sync --from <lockfile>` (per FR-002). The `ContainerFactoryVersionDir`, `ContainerFactoryVersionFile` constants and associated functions are KEPT. `ContainerFactoryVersionIndexFile` and runtime index parsing functions (`ParsePmLock`, `collectInstalledPackets`) are DEAD.

## Technology Choices

### SBOM Cataloger Name

- **Decision**: Use `"os-pm-lock-cataloger"` as the `CatalogerName` for `os-pm`.
- **Rationale**: Consistent with naming pattern of other catalogers (e.g., `"go-module-file-cataloger"`, `"rust-cargo-lock-cataloger"`).
- **Alternatives considered**: `"os-pm-cataloger"` — rejected as too generic; `"pm-sync-cataloger"` — rejected as implementation-specific.

### Lock File Defaults

- **Decision**: `DefaultSpecFile: "pm.yaml"`, `DefaultLockFile: "pm.lock"`.
- **Rationale**: As specified in FR-001 and FR-008. Consistent with user expectations and the pm tool conventions.
- **Alternatives considered**: None.

### Workdir Handling

- **Decision**: Reject `workdir` for `os-pm` at configuration parse time.
- **Rationale**: OS-level package manager operates at system level, not per-project. `pm.yaml` and `pm.lock` always at repository root.
- **Implementation**: Check in `fillFileBasedSpec()` or `validate()` — if type is `os-pm` and `workdir` is set, return error.
## Unknown 5: Build Phase Lock Path Propagation (FR-011)

### Current State

In `pkg/build/build_phase.go`, `convergeImageSbom()` currently:
1. Calls `imageBase.OSPMLockPath()` (the newly renamed method)
2. Reduces it to a boolean `hasOsPmPackages := ospmLockPath != ""`
3. Passes this boolean to `ConvergeWithMerge()` in `pkg/build/sbom_step.go`

In `pkg/build/sbom_step.go`, `ConvergeWithMerge()` uses the boolean to decide whether:
- To run PM-specific SBOM processing
- To trigger the PM cataloger registration

### Target State

Per FR-011, the concrete lock file path must be propagated instead of a boolean:

1. `convergeImageSbom()` passes `ospmLockPath` (string, e.g., `"pm.lock"`) directly to `ConvergeWithMerge()` instead of `hasOsPmPackages bool`.
2. `ConvergeWithMerge()` takes `osPmLockPath string` instead of `osPmEnabled bool`.
3. The lock path is forwarded to the PM BOMPatcher so it can correlate host-scanned PM components.

### Decision

- **Change**: `ConvergeWithMerge()` signature: `osPmEnabled bool` → `osPmLockPath string`. `convergeImageSbom()` passes `imageBase.OSPMLockPath()` directly.
- **Rationale**: The lock file path is needed by the BOMPatcher to identify which host-scanned components need enrichment. A boolean is insufficient.
- **Alternatives considered**: Keep the boolean and add a separate lock path parameter — rejected as redundant; the lock path subsumes the boolean.

## Unknown 6: PM PURL Enrichment via BOMPatcher

### Problem

The Syft cataloger scans `pm.lock` from the build context and produces SBOM components with all package metadata (names, versions, licenses, dependencies). However, these components lack the `containerFactoryVersion` PURL qualifier required by FR-002. This version is only available from inside the built image via `readContainerFactoryVersion()` (which reads `/var/lib/pm/container-factory-version`).

### Approach

After the host scan produces the initial SBOM, a **BOMPatcher** post-processes the components:

1. `ConvergeWithMerge()` in `pkg/build/sbom_step.go` receives the lock file path.
2. It creates a PM BOMPatcher function that:
   - Reads the container factory version from the built image (`readContainerFactoryVersion()`)
   - Iterates over all SBOM components in the merged BOM
   - Finds PM components by checking `syft:package:foundBy` property for `"os-pm-lock-cataloger"`
   - Appends `containerFactoryVersion=<version>` to each matching component's PURL
3. The patcher is added to the `patchers` slice in `convergeImageSbom()` and executed during SBOM merge.

### Where the Patcher Lives

- **Patcher logic**: New file `pkg/sbom/packages/os_pm/pm_bom_patcher.go`
- **Patcher registration**: `pkg/build/sbom_step.go` — inside `ConvergeWithMerge()` or as a helper function in the same file, importing and calling the PM BOMPatcher from `pkg/sbom/packages/os_pm/`
- **Container factory version read**: Reuses `os_pm.readContainerFactoryVersion()` from `pkg/sbom/packages/os_pm/collect.go` (KEPT per FR-010b)

### Decision

- **Change**: Add a PM BOMPatcher that reads container factory version from inside the built image and enriches host-scanned PM components with the `containerFactoryVersion` PURL qualifier.
- **Rationale**: The container factory version is only available inside the built image, not in the build context. Host scanning cannot capture it. The patcher pattern is consistent with how other SBOM enrichment works in the codebase (e.g., existing patchers for other metadata).
- **Entry point**: The patcher is added to the `patchers` slice in `convergeImageSbom()` and invoked by `ConvergeWithMerge()`.
- **Component identification**: Match `syft:package:foundBy = "os-pm-lock-cataloger"`.
