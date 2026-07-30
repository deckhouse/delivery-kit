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

### `GeneratePackagesCommands`

```go
// File: pkg/config/packages_commands.go

// Generates shell commands for each package directive.
// For os-pm type, if the directive has non-empty Env, the command
// is prefixed with 'export KEY1="VAL1" KEY2="VAL2" &&'.
// For nil/empty Env, the behavior is unchanged (backward compatible).
func GeneratePackagesCommands(packages []*PackagesDirective) []string
```

### New helper: `formatEnvExportCommand`

```go
// File: pkg/config/packages_commands.go

// formatEnvExportCommand generates "export KEY1="VAL1" KEY2="VAL2" && ",
// or returns "" if env is nil or empty.
func formatEnvExportCommand(env map[string]string) string
```

### New helper: `validateEnvNames` (or inline in `toDirective`)

```go
// File: pkg/config/raw_packages_directive.go or packages_directive.go

// validateEnvNames checks each key against POSIX ^[a-zA-Z_][a-zA-Z0-9_]*$
// Returns an error with the index of the offending entry.
func validateEnvNames(env map[string]string) error
```

## No Public API Changes

The `PackagesDirective` type is already public (used by `Ecosystems()` and tests). Adding an exported `Env` field is the only public change. No new public functions, types, or interfaces are introduced.
