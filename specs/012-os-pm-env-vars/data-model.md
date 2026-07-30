# Data Model: os-pm Environment Variables

## Entity: rawPackagesDirective (YAML → Raw Go)

```go
type rawPackagesDirective struct {
    Type    string              `yaml:"type,omitempty"`
    Spec    interface{}         `yaml:"spec,omitempty"`
    Workdir string              `yaml:"workdir,omitempty"`
    Lock    string              `yaml:"lock,omitempty"`
    Env     map[string]string   `yaml:"env,omitempty"`   // NEW

    rawStapelImage *rawStapelImage `yaml:"-"`

    UnsupportedAttributes map[string]interface{} `yaml:",inline"`
}
```

### YAML Schema

```yaml
packages:
  - type: os-pm
    spec:
      - curl
      - jq
    env:                          # NEW — optional
      DOCKER_CONFIG: /run/secrets/docker-config
      HTTP_PROXY: http://proxy.example.com:8080
      DEBIAN_FRONTEND: noninteractive
```

### Validation Rules

1. **`env` field type**: MUST be a mapping of string keys to string values at the YAML level. If `env` is a number, boolean, array, or nested structure, the YAML parser should reject it with a clear error. **However**, since YAML is flexible, we must validate the Go side: the `rawPackagesDirective.Env` field is typed as `map[string]string`, so YAML unmarshaling will fail automatically for non-string values (Go YAML library handles this). But for `UnsupportedAttributes` overflow checking, the `env` key must be recognized — adding `Env` to the struct suffices.

2. **POSIX name validation**: Each key in `env` MUST match the POSIX pattern `^[a-zA-Z_][a-zA-Z0-9_]*$`. Invalid names produce a config parse error like:
   ```
   invalid environment variable name %q in packages[%d].env: must match POSIX naming pattern [a-zA-Z_][a-zA-Z0-9_]*
   ```

3. **Value validation**: No validation on values — empty strings are allowed. Values are passed as-is to the shell `export` command, double-quoted for safety.

4. **Empty map**: An empty `env: {}` is equivalent to no `env` — treated as backward compatible.

### State Transitions

**Config parse time** (raw → directive):
```
rawPackagesDirective.Env  ──validate──▶  PackagesDirective.Env
(map[string]string)        POSIX names    (map[string]string)
```

**Build time** (directive → shell command):
```
PackagesDirective.Env  ──▶  export KEY="VALUE" && pm install ...
(PackagesDirective.Env != nil && len > 0)  →  prepend export
(PackagesDirective.Env == nil || len == 0) →  no change (backward compatible)
```

## Entity: PackagesDirective (Validated)

```go
type PackagesDirective struct {
    Type      PackagesDirectiveType
    FileBased FileBasedSpec
    Spec      PackagesSpec
    Env       map[string]string   // NEW — validated POSIX names
}
```

## Entity: PackagesSpec (Unchanged)

```go
type PackagesSpec struct {
    Packages []string   // unchanged
}
```

## Relationships

| Entity | Relationship |
|--------|-------------|
| `rawStapelImage` → `rawPackagesDirective` | Has-many via `RawPackages` |
| `rawPackagesDirective` → `PackagesDirective` | Converted via `toDirective()` |
| `StapelImageBase.Packages` → `PackagesDirective` | Stored as `[]*PackagesDirective` |
| `PackagesDirective.Env` → shell command | Used in command generation only for `os-pm` type |

## Validation Flow

```
YAML input
    │
    ▼
rawPackagesDirective (UnmarshalYAML)
    │  ── Env map[string]string parsed automatically
    ▼
toDirective()
    │  ── POSIX name validation for each env key
    ▼
PackagesDirective
    │  ── Env field populated
    ▼
GeneratePackagesCommands()
    │  ── For os-pm: include env vars in shell command
    ▼
Shell.Packages []string (commands with export prefix)
```
