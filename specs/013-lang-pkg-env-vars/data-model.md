# Data Model: lang-pkg-env-vars

**Branch**: `013-lang-pkg-env-vars` | **Date**: 2026-08-03 | **Spec**: [spec.md](spec.md) | **Research**: [research.md](research.md)

## Entities

### 1. PackagesDirective (pkg/config/packages_directive.go)

The central config entity for all package types (OS and language). This feature does **not** add fields — the `Env` field already exists.

| Field | Type | Description | Constraints |
|-------|------|-------------|-------------|
| `Type` | `PackagesDirectiveType` | Discriminator for package ecosystem | One of the 10 enum values below |
| `FileBased` | `FileBasedSpec` | Language-specific file references | Required for lang types (workdir, spec); ignored for os-pm |
| `Spec` | `PackagesSpec` | Package name list | Required for os-pm; ignored for lang types |
| `Env` | `map[string]string` | User-defined environment variables for the package manager process | Keys validated against POSIX naming rules at parse time |

### 2. PackagesDirectiveType (enum)

| Constant | Value | Ecosystem | Install Command |
|----------|-------|-----------|----------------|
| `PackagesDirectiveTypeOSPM` | `os-pm` | OS package manager (apt, yum) | `pm install` |
| `PackagesDirectiveTypeGoMod` | `go-mod` | Go modules | `go mod download` |
| `PackagesDirectiveTypePythonUV` | `python-uv` | Python (uv) | `uv sync --frozen` |
| `PackagesDirectiveTypePythonPip` | `python-pip` | Python (pip) | `pip install --no-cache-dir -r <spec>` |
| `PackagesDirectiveTypePythonPoetry` | `python-poetry` | Python (poetry) | `poetry sync --no-root` |
| `PackagesDirectiveTypeRustCargo` | `rust-cargo` | Rust (Cargo) | `cargo fetch` |
| `PackagesDirectiveTypeJavaScriptNpm` | `javascript-npm` | JavaScript (npm) | `npm ci` |
| `PackagesDirectiveTypeJavaScriptYarn` | `javascript-yarn` | JavaScript (Yarn) | `yarn install --frozen-lockfile` |
| `PackagesDirectiveTypeJavaScriptPnpm` | `javascript-pnpm` | JavaScript (pnpm) | `pnpm install --frozen-lockfile` |
| `PackagesDirectiveTypeLuaRock` | `lua-rock` | Lua (Luarocks) | `luarocks install --only-deps <spec>` |

### 3. FileBasedSpec (pkg/config/packages_directive.go)

Language-specific file path configuration.

| Field | Type | Description |
|-------|------|-------------|
| `Workdir` | `string` | Working directory for the install command |
| `Spec` | `string` | Path to the spec file (e.g., `go.mod`, `requirements.txt`) |
| `Lock` | `string` | Path to the lock file (e.g., `go.sum`, `package-lock.json`) |

### 4. PackageEcosystem (pkg/config/packages_directive.go)

Registry entry linking a package type to its install behavior.

| Field | Type | Description |
|-------|------|-------------|
| `Type` | `PackagesDirectiveType` | The type this ecosystem entry handles |
| `DefaultSpecFile` | `string` | Default spec filename (e.g., `go.mod`) |
| `DefaultLockFile` | `string` | Default lock filename (e.g., `go.sum`) |
| `InstallCmd` | `func(workdir, specFile string, specList []string, env map[string]string) string` | Function that generates the shell command string |
| `CatalogerName` | `string` | SBOM cataloger identifier |

## Relationships

```mermaid
flowchart LR
    A[werf.yaml<br>packages[]] -->|parsed by| B[rawPackagesDirective]
    B -->|validated by| C[rawPackagesDirective.toDirective]
    C --> D[PackagesDirective<br>.Type .FileBased .Spec .Env]
    D -->|dispatched by| E[GeneratePackagesCommands]
    E -->|looks up| F[ecosystems map]
    F -->|calls| G[InstallCmd func]
    G -->|produces| H["shell command string<br>with env prefix"]
    H -->|stored in| I[Shell.Packages]
    I -->|executed by| J[PackagesStage<br>PrepareImage]
    J -->|writes to| K[container script]
    K -->|runs in| L[build container]
```

## Validation Rules

### Env Var Name Validation (pkg/config/raw_packages_directive.go)

- **Rule**: Each key in `env` must match `^[a-zA-Z_][a-zA-Z0-9_]*$` (POSIX environment variable naming).
- **Error**: `invalid environment variable name %q in packages[%d].env: must match POSIX naming pattern [a-zA-Z_][a-zA-Z0-9_]*`
- **Scope**: Applied to **all** package types (OS and language) — no change needed for this feature.

### Env Var Empty/Nil Handling

- If `env` is `nil` or empty map → no prefix prepended → command is identical to pre-feature behavior (backward compatibility maintained).

### Env Var Shadowing

- Per-dependency-scoped: each `packages[].env` entry is scoped to its own command invocation. Overriding system env vars like `HTTP_PROXY` affects only that package manager process, not the broader build process or other package entries.

### SBOM Gate

- `GeneratePackagesCommands()` is only called when `meta.Build.Sbom != nil && meta.Build.Sbom.Enable` is true (see `raw_stapel_image.go:329`). Without SBOM, `Shell.Packages` remains empty and no package commands are executed at all (existing behavior, unchanged by this feature).

## State Transitions

The env var wiring has no state machine — it is a data transformation pipeline:

1. **Parse**: `rawPackagesDirective.Env` is populated from YAML and POSIX-validated.
2. **Store**: Validated `PackagesDirective.Env` is stored on the directive.
3. **Generate**: `GeneratePackagesCommands()` reads `PackagesDirective.Env` and passes it to `InstallCmd`.
4. **Render**: `InstallCmd` calls `formatEnvVars(env)` to produce an inline shell prefix.
5. **Execute**: The resulting string (env prefix + install command) runs in the container via `Shell.Packages`.