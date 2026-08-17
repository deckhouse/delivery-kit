# Data Model: Inline os-pm Syntax

**Date**: 2026-08-13 | **Branch**: `017-inline-os-pm-syntax-again`

## Entities

### `PackagesSpec`

The inline specification data for OS package declarations. Restored from the 009 era with support for environment variables per section.

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `Packages` | `[]string` | Yes | Inline list of OS package names with optional version constraints (e.g., `["curl==8.12.1", "jq"]`) |

**Validation rules**:
- MUST contain at least one package name
- MUST NOT be empty
- Package name content is NOT validated by delivery-kit — validation is `pm`'s responsibility. Delivery-kit only checks that the list is non-empty. `pm` supports both `==` and `@` version constraint syntax (e.g., `curl==8.12.1` or `curl@8.12.1`).

**Go definition** (in `pkg/config/packages_directive.go`):
```go
type PackagesSpec struct {
    Packages []string `yaml:"spec"`
}
```

### `OsPmDirective` (effective — represented by `PackagesDirective` with `Type == "os-pm"`)

The `os-pm` directive in `werf.yaml`. This is a case of the general `PackagesDirective` struct, with type-specific constraints.

| Field | Source | Required | Description |
|-------|--------|----------|-------------|
| `Type` | `PackagesDirective.Type` | Yes | MUST be `"os-pm"` |
| `Spec.Packages` | `PackagesSpec.Packages` | Yes | Inline list of package names |
| `Env` | `PackagesDirective.Env` | No | Environment variables for the pm command (e.g., `REGISTRY`, `PACKAGES_VERSION`) |
| `Workdir` | N/A | N/A | NOT applicable — rejected at validation |

**State machine**: None — `os-pm` directives are static configuration that is read once during config parsing and used during build.

### `FileBasedSpec` (unchanged, but no longer used by `os-pm`)

Kept for completeness — used by other package types (`go-mod`, etc.):

```go
type FileBasedSpec struct {
    Workdir string
    Spec    string
    Lock    string
}
```

### `PackageEcosystem` (updated `os-pm` entry)

Configuration for the `os-pm` ecosystem. Changes from 015:

| Field | 015 Value | 017 Value |
|-------|-----------|-----------|
| `Type` | `"os-pm"` | `"os-pm"` (unchanged) |
| `DefaultSpecFile` | `"pm.yaml"` | `""` |
| `DefaultLockFile` | `"pm.lock"` | `""` |
| `CatalogerName` | `"os-pm-lock-cataloger"` | `"os-pm-cataloger"` — owned by `pkg/sbom/packages/os_pm` |
| `InstallCmd` | `pm sync --from <lockfile>` | `pm install <pkgs>` |

### `PmInstallCommand`

The generated shell command that installs OS packages. Structure:

```
# Preamble (from formatMkdirCommand, formatVersionFileCommand)
mkdir -p /var/lib/pm
echo "$PACKAGES_VERSION" > /var/lib/pm/container-factory-version

# Install command with inline env vars
REGISTRY=internal-registry.example.com pm install curl==8.12.1 jq
```

**Generation**: Created by `formatInstallCommand(pkgs []string, env map[string]string) string` in `pkg/config/packages_commands.go`.

## Image File Artifacts

### `/var/lib/pm/index.json`

Flat JSON object mapping package names to package info. Format:

```json
{
    "curl": {
        "name": "curl",
        "version": "8.12.1",
        "description": "A utility for file transfer",
        "license": "MIT",
        "homepage": "https://curl.se/",
        "source": {
            "type": "deb",
            "url": "http://deb.debian.org/debian"
        },
        "dependencies": ["libcurl4", "ca-certificates"]
    },
    "jq": { ... }
}
```

**Read by**: `CollectBOM()` in `pkg/sbom/packages/os_pm`; the path is provided by an os-pm package constant and is not duplicated in the build layer.

**Producer**: The `pm` binary inside the builder image during the build stage.

**Consumer**: `CollectBOM()` during SBOM generation.

### `/var/lib/pm/container-factory-version`

Text file containing the container factory version string.

**Written during build by**: The command preamble (`PACKAGES_VERSION` → file write).

**Read during SBOM collection by**: `ReadContainerFactoryVersion()` from inside the built image.

**Fallback**: If file doesn't exist in image, the value comes from `PACKAGES_VERSION` environment variable (available during sbom collection if passed through).

## SBOM Pipeline Invariant

The os-pm SBOM package produces and integrates the runtime component set from the final image state before `externalref.ExternalRefPatcher` runs. `pkg/build` coordinates this operation but does not append components or dependencies itself. Consequently, every component with a resolvable PURL, including `curl`/`openssl` supplied by the runtime index, participates in external-reference enrichment.

If enrichment fails for one or more components, the error retains `ErrExternalRefEnrich` and component details so `BuildPhase` can continue independent images and produce a hierarchical aggregate. A successful image must not appear in the aggregate.

The SBOM cache key/annotation is part of this pipeline contract: cache reuse is valid only when it represents the same final-BOM inputs and enrichment behavior. A format/order change that can reuse an older artifact must be represented in the checksum/version or otherwise invalidated.

## Relationships

```
werf.yaml
  └── packages[] (list of package directives)
        └── type: "os-pm"
              └── spec: []string (inline package list) ──→ PackagesSpec.Packages
              └── env: map[string]string (optional)   ──→ Env
                    │
                    ▼
              GeneratePackagesCommands()
                    │
                    ▼
              formatInstallCommand(pkgs, env)
                    │
                    ▼
              Shell command string: "pm install <pkgs>"
                    │
                    ▼
              [Build Stage] ──→ runs command in container
                    │
                    ▼
              /var/lib/pm/index.json ←─ written by pm binary
                    │
                    ▼
              `pkg/sbom/packages/os_pm` runtime BOM operation
                    │
                    ├── ReadFileFromImage(indexPath constant)
                    ├── ParsePmInstalledJSON()
                    ├── ReadContainerFactoryVersion() (or env)
                    └── ConvertToCycloneDX() and integrate into final BOM
                          │
                          ▼
                    CycloneDX BOM ──→ generic patchers
```
