# Data Model: os-pm File-Based Syntax

## Package Ecosystem Entry (os-pm)

Registration in the `ecosystems` map in `pkg/config/packages_directive.go`:

| Field | Value | Description |
|-------|-------|-------------|
| `Type` | `PackagesDirectiveTypeOSPM` | `"os-pm"` |
| `DefaultSpecFile` | `"pm.yaml"` | Default spec file name (replaces inline `[]string`) |
| `DefaultLockFile` | `"pm.lock"` | Default lock file name |
| `CatalogerName` | `"os-pm-lock-cataloger"` | SBOM cataloger identifier |
| `InstallCmd` | See below | Generates `pm sync --from <lockfile>` preceded by container factory version preamble (per FR-002) |

### InstallCmd Logic

```text
Input:
  - workdir: (ignored for os-pm, always empty)
  - specFile: e.g., "pm.yaml" (used for SBOM, not for install command)
  - specList: [] (unused for file-based os-pm)
  - lockFile: e.g., "pm.lock" (used for --from flag)
  - env: map of environment variables

Output:
  <mkdir -p /var/lib/pm> ; <container factory version file write> ; <env prefix> <secret vars> pm sync --from <lockFile>

Example (without env vars):
  mkdir -p /var/lib/pm ; PACKAGES_VERSION="${PACKAGES_VERSION:-$(cat ...)}" && printf '%s\n' "$PACKAGES_VERSION" > /var/lib/pm/container-factory-version ; PACKAGES_VERSION="${PACKAGES_VERSION:-$(cat ...)}" REGISTRY="${REGISTRY:-$(cat ...)}" pm sync --from pm.lock

Example (with env vars):
  mkdir -p /var/lib/pm ; PACKAGES_VERSION="${PACKAGES_VERSION:-$(cat ...)}" && printf '%s\n' "$PACKAGES_VERSION" > /var/lib/pm/container-factory-version ; MY_ENV="value" PACKAGES_VERSION="${PACKAGES_VERSION:-$(cat ...)}" REGISTRY="${REGISTRY:-$(cat ...)}" pm sync --from pm.lock
```

> **Note**: The `GeneratePackagesCommands()` function currently calls `InstallCmd` with 4 parameters `(workdir, specFile, specList, env)`. The list-based `specList` parameter is not needed for file-based `os-pm`. The lock file path is resolved from the `PackagesDirective.FileBased.Lock` field by the caller. The container factory version preamble (`formatMkdirCommand`, `formatVersionFileCommand`) is PRESERVED per FR-002 — it writes `ContainerFactoryVersionFile` for the SBOM purl qualifier. The runtime index file (`ContainerFactoryVersionIndexFile`) is NOT written — package data comes from `pm.lock` in build context.

## PackagesDirective Struct

**Current** (`pkg/config/packages_directive.go`):
```go
type PackagesDirective struct {
    Type      PackagesDirectiveType
    FileBased FileBasedSpec
    Spec      PackagesSpec      // ← REMOVE: only used for inline os-pm
    Env       map[string]string
}
```

**Target**:
```go
type PackagesDirective struct {
    Type      PackagesDirectiveType
    FileBased FileBasedSpec      // ← Now used for ALL package types including os-pm
    Env       map[string]string
}
```

## FileBasedSpec Struct

**Remains unchanged** (`pkg/config/common.go`):
```go
type FileBasedSpec struct {
    Workdir string  // Rejected for os-pm (validated at parse time)
    Spec    string  // Defaults to "pm.yaml" for os-pm
    Lock    string  // Defaults to "pm.lock" for os-pm
}
```

### For `os-pm`, the semantics are:
- **Workdir**: Always empty (repo root). Setting `workdir` for `os-pm` → validation error.
- **Spec**: Path to `pm.yaml` (relative to repo root). Defaults to `"pm.yaml"`.
- **Lock**: Path to `pm.lock` (relative to repo root). Defaults to `"pm.lock"`. Optional — when omitted, `pm.lock` is assumed.

## PackagesSpec Struct (to be removed)

```go
type PackagesSpec struct {     // ← REMOVE entirely
    Packages []string
}
```

## SBOM Integration

### managedinput.go Source Paths

For `os-pm`, the SBOM cataloger will receive source paths:
```go
sourcePaths: func(d *config.PackagesDirective) []string {
    // d.FileBased.Workdir is always "" for os-pm
    return []string{
        path.Join(d.FileBased.Workdir, d.FileBased.Spec),   // e.g., "pm.yaml"
        path.Join(d.FileBased.Workdir, d.FileBased.Lock),   // e.g., "pm.lock"
    }
},
workdir: func(d *config.PackagesDirective) string {
    return d.FileBased.Workdir  // "" for os-pm
},
```

This is automatically derived from `FileBasedSpec` — no special-casing needed in `managedinput.go`.

### PM BOMPatcher (PURL Enrichment)

After the Syft cataloger scans `pm.lock` from the build context, the resulting SBOM components lack the `containerFactoryVersion` PURL qualifier. This version only exists inside the built image (`/var/lib/pm/container-factory-version`).

- **Entity**: `PMBOMPatcher` — post-processes the merged BOM
- **Where**: Created in `pkg/build/sbom_step.go`, invoked by `ConvergeWithMerge()`
- **Input**: Container factory version from `readContainerFactoryVersion()` (reuses `os_pm/collect.go`)
- **Identification**: Matches PM components via `syft:package:foundBy = "os-pm-lock-cataloger"`
- **Effect**: Appends `containerFactoryVersion=<version>` to each PM component's PURL
- **Trigger**: Only active when `osPmLockPath` is non-empty (i.e., `os-pm` packages are configured)

## Configuration YAML Schema

### Accepted (new file-based syntax):
```yaml
packages:
  - type: os-pm
```
→ `spec: "pm.yaml"`, `lock: "pm.lock"` (defaults), `workdir: ""` (repo root)

```yaml
packages:
  - type: os-pm
    spec: custom-pm.yaml
    lock: custom.lock
```
→ Overrides defaults with custom file paths.

### Rejected:
```yaml
packages:
  - type: os-pm
    spec: [curl, jq]      # ERROR: spec must be a string, not a list
```

```yaml
packages:
  - type: os-pm
    workdir: /app          # ERROR: workdir not accepted for os-pm
```

## State Transitions

No state machine — this is a configuration-only change. The transition is:

1. User writes `pm.yaml` with package specs
2. User runs `pm lock --from=pm.yaml` locally → generates `pm.lock`
3. User commits both files
4. User configures `werf.yaml` with `packages: [{type: os-pm}]`
5. Werf parses config → resolves default spec/lock → generates `pm sync --from pm.lock`
6. Build executes the command inside the container → packages installed
7. SBOM scans `pm.yaml` and `pm.lock` from build context → generates component metadata

## Validation Rules

| Field | Rule | Error Message |
|-------|------|---------------|
| `spec` (for os-pm) | Must be a string (file path) | `"unsupported packages spec type %T for type "os-pm"; spec must be a string"` |
| `workdir` (for os-pm) | Must NOT be set | `"workdir is not supported for type "os-pm""` |
| `spec` file existence | Must exist in repository | `"pm.yaml not found at <path>"` |
| `lock` file existence | Must exist if `pm.yaml` exists | `"pm.lock not found at <path>. Run 'pm lock' in your repository to generate the lock file, commit it, and retry."` |
| `spec` + `lock` absence | Both must exist (lock can use defaults) | Build fails with file-not-found error |