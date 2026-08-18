# Contracts: Inline os-pm Syntax

**Date**: 2026-08-13 | **Branch**: `017-inline-os-pm-syntax-again`

## Contract 1: werf.yaml Config Schema (User-facing)

The `os-pm` package type accepts **only** inline `spec` as a list of strings. This is the user-facing contract for declaring OS packages.

### Schema

```yaml
packages:
  - type: os-pm
    spec:
      - <package-name>[==<version>]
      - <package-name>[==<version>]
    # Optional:
    env:
      <KEY>: <value>
```

**Note**: `pm` also supports `@` syntax for version constraints (e.g., `curl@8.12.1`). Delivery-kit passes the package list as-is without interpreting version formats.

### Examples

```yaml
# Single os-pm section
packages:
  - type: os-pm
    spec:
      - curl==8.12.1
      - jq

# Multiple os-pm sections with different env
packages:
  - type: os-pm
    spec:
      - curl==8.12.1
  - type: os-pm
    spec:
      - custom-pkg==2.0.0
    env:
      REGISTRY: internal-registry.example.com
```

### Validation Rules

| Rule | Condition | Error |
|------|-----------|-------|
| spec must be a list, not a string path | `spec` is a string (file path) | `"os-pm spec must be a list of package names, not a file path"` |
| spec must not be empty | `spec` is empty list | `"os-pm spec must contain at least one package"` |
| workdir not allowed | `workdir` is set | `"os-pm does not support workdir"` |
| env is optional | `env` is map | Allowed; keys become shell env vars |

**Note**: Delivery-kit does not validate individual package name formats — it passes the list as-is to `pm install`. Package name validation is `pm`'s responsibility.

### Removed Syntax (from 015)

The following is **no longer valid** for `os-pm`:

```yaml
# NOT VALID for os-pm (file-based syntax removed)
packages:
  - type: os-pm
    spec: pm.yaml
    lock: pm.lock
```

## Contract 2: `GeneratePackagesCommands` — Command Generation Interface

**File**: `pkg/config/packages_commands.go`

Command generation MUST reuse `os_pm.ContainerFactoryIndexPath` and `os_pm.ContainerFactoryVersionPath`; `pkg/config` must not define duplicate PM path constants.

### Current Signature (015)

```go
func GeneratePackagesCommands(
    packages []*PackagesDirective,
) []string
```

No change to this function's signature. The generated commands change from `pm sync --from <lockfile>` to `pm install <pkg1> <pkg2> ...` for `os-pm`.

### `PackageEcosystem.InstallCmd` — Changed Signature

**Before (015)**:
```go
type PackageEcosystem struct {
    InstallCmd func(workdir, specFile, lockFile string, env map[string]string) string
}
```

**After (017)**:
```go
type PackageEcosystem struct {
    InstallCmd func(workdir string, files FileBasedSpec, pkgs []string, env map[string]string) string
}
```

**Rationale**: `os-pm` needs the inline package list. Other ecosystems pass their `FileBasedSpec` as before (unchanged behavior). The `pkgs` slice is empty for non-os-pm types.

### New Function: `formatInstallCommand`

```go
func formatInstallCommand(pkgs []string, env map[string]string) string
```

Returns the complete shell command string, including the preamble, sorted env prefixes, separators, quoting, and package arguments. The implementation forms the command prefix, environment-prefix string, install command, and final semicolon-joined result as clearly named steps. Every env case compares the complete result with `Equal(expected)` rather than checking substrings. The env prefixes must be on the same invocation as `pm install`, never separated by `;`:
```
mkdir -p /var/lib/pm; PACKAGES_VERSION=... REGISTRY=internal-registry.example.com CUSTOM_VAR="value" pm install curl==8.12.1 jq
```

## Contract 3: SBOM Collection Interface

### `CollectBOM` — Restored

**File**: `pkg/sbom/packages/os_pm/collect.go`

```go
func CollectBOM(
    ctx context.Context,
    containerBackend container_backend.ContainerBackend,
    imageRef string,
) (*cdx.BOM, error)
```

**Behavior**:
1. Read mandatory `ContainerFactoryIndexPath` (`/var/lib/pm/index.json`) from inside the built image via `ReadFileFromImage`; the constant is defined once in `pkg/sbom/os_pm/metadata`. An absent index is an error.
2. Parse as `map[string]PmPackageInfo` via `ParsePmInstalledJSON`.
3. Resolve `containerFactoryVersion` by reading `ContainerFactoryVersionPath` from `pkg/sbom/os_pm/metadata` internally; do not expose a redundant public version-reading wrapper and do not read `PACKAGES_VERSION` from the host process. Write version-read errors to debug logging with image/path context while preserving the agreed collector error behavior.
4. Convert to CycloneDX BOM via `ConvertToCycloneDX`.
5. Provide the runtime contribution to the final-BOM operation before generic external-reference patchers; return no os-pm contribution with nil error only when the mandatory index is valid but contains no packages.

### Version provenance handling — internal

Version reading remains an internal operation of `CollectBOM`; no redundant exported `ReadContainerFactoryVersion` wrapper is added. The command preamble writes `ContainerFactoryVersionPath` from the container-scoped `PACKAGES_VERSION`; the collector does not use a host-env fallback. Read errors are written to debug logging with image/path context, and command generation reuses the metadata constant instead of redeclaring the path.

## Contract 4: `StapelImageBase` — Changed Interface

**File**: `pkg/config/stapel_image_base.go`

### Removed Methods

```go
// REMOVED — no longer applicable
func (b *StapelImageBase) OSPMLockPath() string
func (b *StapelImageBase) OSPMSpecPath() string
```

### Restored Method

```go
// Check whether the image has any os-pm packages declared
func (b *StapelImageBase) HasOSPMPackages() bool
```

## Contract 5: Build Phase — Changed Signature

### `sbom_step.go` — `ConvergeWithMerge`

```go
// Historical 015 shape:
func (s *SbomStep) ConvergeWithMerge(
    ctx context.Context,
    osPmLockPath string,  // ← lock file path
    ...
)

// Current 017 coordination shape:
func (s *SbomStep) ConvergeWithMerge(
    ctx context.Context,
    osPmEnabled bool,  // ← boolean gate; os-pm details stay in pkg/sbom/packages/os_pm
    ...
)
```
