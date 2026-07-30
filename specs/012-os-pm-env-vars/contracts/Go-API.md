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
// For os-pm type, if the directive has non-empty Env, the env vars
// are prepended as inline prefix before `pm install`:
//   KEY="VAL1" KEY2="VAL2" pm install ...
// For nil/empty Env, the behavior is unchanged (backward compatible).
func GeneratePackagesCommands(packages []*PackagesDirective) []string
```

### Updated helper: `formatInstallCommand`

The existing function gains env vars support. User-defined env vars from `PackagesDirective.Env` are prepended inline alongside the existing `PACKAGES_VERSION` and `REGISTRY` vars:

```
PACKAGES_VERSION="${...}" REGISTRY="${...}" USER_VAR1="val1" USER_VAR2="val2" pm install pkg1 pkg2
```

### No new helper needed

The env vars are merged directly into the existing `formatInstallCommand` call — no new public or internal function is required. The generation code prepends each `key="value"` from `Env` to the existing env var prefix of the `pm install` command.

## No Public API Changes

The `PackagesDirective` type is already public (used by `Ecosystems()` and tests). Adding an exported `Env` field is the only public change. No new public functions, types, or interfaces are introduced.
