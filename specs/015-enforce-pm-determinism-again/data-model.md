# Data Model: os-pm File-Based Syntax

## Package Ecosystem Entry (os-pm)

Registration in the `ecosystems` map in `pkg/config/packages_directive.go`:

| Field | Value | Description |
|-------|-------|-------------|
| `Type` | `PackagesDirectiveTypeOSPM` | `"os-pm"` |
| `DefaultSpecFile` | `"pm.yaml"` | Default spec file name (replaces inline `[]string`) |
| `DefaultLockFile` | `"pm.lock"` | Default lock file name |
| `CatalogerName` | `"os-pm-lock-cataloger"` | SBOM cataloger identifier |
| `InstallCmd` | See below | Generates `pm sync --from <lockfile>` with container factory version snapshot |

### InstallCmd Logic

```text
Input:
  - workdir: (ignored for os-pm, always empty)
  - specFile: e.g., "pm.yaml" (used for SBOM, not for install command)
  - specList: [] (unused for file-based os-pm)
  - lockFile: e.g., "pm.lock" (used for --from flag)
  - env: map of environment variables

Output:
  <mkdir -p /var/lib/pm> ; <version snapshot> ; <env prefix> <secret vars> pm sync --from <lockFile>

Example:
  mkdir -p /var/lib/pm ; PACKAGES_VERSION="${PACKAGES_VERSION:-$(cat ...)}" && printf '%s\n' "$PACKAGES_VERSION" > /var/lib/pm/container-factory-version ; PACKAGES_VERSION="${PACKAGES_VERSION:-$(cat ...)}" REGISTRY="${REGISTRY:-$(cat ...)}" MY_ENV="value" pm sync --from pm.lock
```

> **Note**: The `GeneratePackagesCommands()` function currently calls `InstallCmd` with 4 parameters `(workdir, specFile, specList, env)`. The list-based `specList` parameter is not needed for file-based `os-pm`. The lock file path is resolved from the `PackagesDirective.FileBased.Lock` field by the caller, so `InstallCmd` should receive it via a changed function signature or through the existing parameters.

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