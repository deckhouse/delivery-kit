# Contract: YAML Config Schema for JavaScript Package Types

## Contract Type

YAML configuration schema for the `packages` directive in `werf.yaml`.

## Schema

### `javascript-npm` type

```yaml
packages:
  - type: javascript-npm
    workdir: /app                           # Required
    spec: package.json                      # Optional (default: package.json)
    lock: package-lock.json                 # Optional (default: package-lock.json)
```

### `javascript-yarn` type

```yaml
packages:
  - type: javascript-yarn
    workdir: /app                           # Required
    spec: package.json                      # Optional (default: package.json)
    lock: yarn.lock                         # Optional (default: yarn.lock)
```

### `javascript-pnpm` type

```yaml
packages:
  - type: javascript-pnpm
    workdir: /app                           # Required
    spec: package.json                      # Optional (default: package.json)
    lock: pnpm-lock.yaml                    # Optional (default: pnpm-lock.yaml)
```

## Contract Semantics

### `type` (required)

- Type: `string`
- Valid values: `javascript-npm`, `javascript-yarn`, `javascript-pnpm`
- The value must match exactly; aliases are not supported
- Each type selects a specific package manager and its install command

### `workdir` (required)

- Type: `string`
- The directory inside the build container where the spec and lock files are located
- Must be non-empty; validated at config parse time

### `spec` (optional)

- Type: `string`
- Default: `package.json` (all three types)
- The manifest file path, relative to `workdir`
- Used by `javascript-package-cataloger` for direct dependency metadata

### `lock` (optional)

- Type: `string`
- Defaults:
  - `javascript-npm`: `package-lock.json`
  - `javascript-yarn`: `yarn.lock`
  - `javascript-pnpm`: `pnpm-lock.yaml`
- The lock file path, relative to `workdir`
- Used by `javascript-lock-cataloger` for transitive dependency SBOM

## Validation Rules

| Rule | Error |
|------|-------|
| Missing `type` | YAML parse error (missing field) |
| Unsupported `type` value | `unsupported packages type "<value>"` |
| Missing `workdir` for JavaScript type | `the "workdir" is required for type "javascript-*"` |
| Empty `workdir` | Same as missing |
| Multiple entries of same/different JavaScript types | Allowed (monorepo support) |
| Mixing JavaScript types with other types | Allowed (e.g., `go-mod` + `javascript-npm`) |

## Wire Format (internal)

After YAML parsing, each JavaScript directive is converted to a `*config.PackagesDirective`:

```go
&config.PackagesDirective{
    Type: config.PackagesDirectiveTypeJavaScriptNpm, // or JavaScriptYarn, JavaScriptPnpm
    FileBased: config.FileBasedSpec{
        Workdir: "/app",             // from YAML
        Spec:    "package.json",     // from YAML or default
        Lock:    "package-lock.json", // from YAML or default
    },
}
```