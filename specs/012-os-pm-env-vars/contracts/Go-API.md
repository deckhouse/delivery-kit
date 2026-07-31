# Go API Contract: Environment Variables for Packages

## Public Types (Changes)

### `PackagesDirective` — new `Env` field

```go
// File: pkg/config/packages_directive.go

type PackagesDirective struct {
    Type      PackagesDirectiveType
    FileBased FileBasedSpec
    Spec      PackagesSpec
    Env       map[string]string  // NEW: validated POSIX env vars to pass to package manager
}
```

## Internal Types (Changes)

### `rawPackagesDirective` — new `Env` field

```go
// File: pkg/config/raw_packages_directive.go

type rawPackagesDirective struct {
    Type    string              `yaml:"type,omitempty"`
    Spec    interface{}         `yaml:"spec,omitempty"`
    Workdir string              `yaml:"workdir,omitempty"`
    Lock    string              `yaml:"lock,omitempty"`
    Env     map[string]string   `yaml:"env,omitempty"`  // NEW
    // ...
}
```

## Functions (Changes)

### `PackageEcosystem` — `InstallCmd` signature gets `env`

```go
// File: pkg/config/packages_directive.go

type PackageEcosystem struct {
    Type            PackagesDirectiveType
    DefaultSpecFile string
    DefaultLockFile string
    InstallCmd      func(workdir, specFile string, specList []string, env map[string]string) string
    CatalogerName   string
}
```

The new `env` parameter is only used by the `os-pm` ecosystem. Other ecosystems ignore it.

### `GeneratePackagesCommands`

```go
// File: pkg/config/packages_commands.go

// Generates shell commands for each package directive.
// For os-pm type, env vars are integrated directly by `formatInstallCommand`
// (via `formatEnvVars`) — no post-processing.
// For nil/empty Env, the behavior is unchanged (backward compatible).
func GeneratePackagesCommands(packages []*PackagesDirective) []string
```

No post-processing: the entire command is produced by `eco.InstallCmd(...)` alone.

### New function: `formatEnvVars`

```go
// File: pkg/config/packages_commands.go

// formatEnvVars formats user-defined env vars as inline shell prefix.
// Uses lo.Map for mapping keys to formatted strings.
// Returns empty string when env is nil or empty.
func formatEnvVars(env map[string]string) string
```

Produces: `KEY1="val1" KEY2="val2"`

Implementation approach:
```go
func formatEnvVars(env map[string]string) string {
    if len(env) == 0 {
        return ""
    }
    keys := lo.Keys(env)
    sort.Strings(keys)
    parts := lo.Map(keys, func(k string, _ int) string {
        return fmt.Sprintf(`%s=%q`, k, env[k])
    })
    return strings.Join(parts, " ")
}
```

### Renamed: `envVarTmpl` → `formatSecretVar`

```go
// File: pkg/config/packages_commands.go

// formatSecretVar generates the PACKAGES_VERSION/REGISTRY secret-resolution template
// (renamed from envVarTmpl for clarity).
func formatSecretVar(name string) string
```

### `formatInstallCommand`

```go
// File: pkg/config/packages_commands.go

// formatInstallCommand now accepts env vars and uses both formatEnvVars and formatSecretVar.
// No post-processing: the complete command is built in a single composition.
func formatInstallCommand(pkgs []string, env map[string]string) string
```

Generates:
```
DOCKER_CONFIG="/run/secrets/config.json" PACKAGES_VERSION="${PACKAGES_VERSION:-$(...)}" REGISTRY="${REGISTRY:-$(...)}" pm install pkg1 pkg2
```

### New validation helper: `validateEnvNames`

```go
// File: pkg/config/raw_packages_directive.go or packages_directive.go

// validateEnvNames checks each key against POSIX ^[a-zA-Z_][a-zA-Z0-9_]*$
func validateEnvNames(env map[string]string) error
```

## Tests (Changes)

### `packages_commands_test.go`

- Existing `It`-based tests for no-env os-pm preserved (backward compat)
- All new tests for `GeneratePackagesCommands` with env vars prefer `DescribeTable` (table-driven) over individual `It` blocks:
  - Single env var, multiple env vars sorted alphabetically, empty string value, DOCKER_CONFIG path, proxy vars, etc.
- Tests for "non-os-pm ignores env" also use `DescribeTable`
- `formatEnvVars` and `formatSecretVar` tests use `DescribeTable` where possible

### `raw_packages_directive_test.go`
- New `DescribeTable` entries for invalid env var names (POSIX validation)
