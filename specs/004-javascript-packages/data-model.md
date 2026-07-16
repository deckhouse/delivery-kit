# Data Model: JavaScript Package Ecosystems

## Overview

This feature adds three new constants and three new entries to the existing `ecosystems` map. No new types, structs, or interfaces are introduced. The existing `FileBasedSpec` and `PackageEcosystem` types are reused as-is.

## Constants

Three new `PackagesDirectiveType` constants added to `pkg/config/packages_directive.go`:

```go
const (
    // ... existing constants ...
    PackagesDirectiveTypeJavaScriptNpm  PackagesDirectiveType = "javascript-npm"
    PackagesDirectiveTypeJavaScriptYarn PackagesDirectiveType = "javascript-yarn"
    PackagesDirectiveTypeJavaScriptPnpm PackagesDirectiveType = "javascript-pnpm"
)
```

## Ecosystem Registry Entries

The `PackageEcosystem` struct (unchanged):

| Field | Type | Purpose |
|-------|------|---------|
| `Type` | `PackagesDirectiveType` | Canonical type constant |
| `DefaultSpec` | `string` | Default manifest file name |
| `DefaultLock` | `string` | Default lock file name (empty if not applicable) |
| `InstallCmd` | `func(workdir, spec string) string` | Function returning the package manager install command |
| `CatalogerName` | `string` | Syft cataloger for SBOM generation |

### JavaScript Entries

| Type | DefaultSpec | DefaultLock | InstallCmd | CatalogerName |
|------|-------------|-------------|------------|---------------|
| `javascript-npm` | `package.json` | `package-lock.json` | `cd "<workdir>" && npm ci` | `javascript-lock-cataloger` |
| `javascript-yarn` | `package.json` | `yarn.lock` | `cd "<workdir>" && yarn install --frozen-lockfile` | `javascript-lock-cataloger` |
| `javascript-pnpm` | `package.json` | `pnpm-lock.yaml` | `cd "<workdir>" && pnpm install --frozen-lockfile` | `javascript-lock-cataloger` |

## FileBasedSpec (reused, unchanged)

```go
type FileBasedSpec struct {
    Workdir string
    Spec    string
    Lock    string
}
```

The `fillFileBasedSpec` function fills defaults from the ecosystem registry. For JavaScript types:

- If `spec` is not provided, defaults to `package.json` (all three types)
- If `lock` is not provided, defaults to the type-specific lock file (`package-lock.json`, `yarn.lock`, or `pnpm-lock.yaml`)
- If `workdir` is empty, the directive is rejected at validation

## Validation Rules

- `javascript-npm`, `javascript-yarn`, `javascript-pnpm` entries require `workdir` (enforced by existing `validate()`)
- `spec` and `lock` are optional; defaults come from the ecosystem registry
- Unknown type strings (e.g., `javascript-bower`, `js-npm`, `npm`) are rejected with "unsupported packages type" error
- Each entry is self-contained; multiple entries of the same type or different types are allowed (monorepo support)

## State Transitions

Not applicable — this feature adds static configuration constants and registry entries. There is no runtime state to manage.

## Relationships

```
PackagesDirective
├── Type: PackagesDirectiveType (one of the JavaScript constants)
└── FileBased:
    ├── Workdir: string
    ├── Spec: string (defaults from ecosystem registry)
    └── Lock: string (defaults from ecosystem registry)
         │
         ▼
    PackageEcosystem (lookup by Type)
    ├── InstallCmd: generates "cd <workdir> && <command>"
    └── CatalogerName: "javascript-lock-cataloger"
         │
         ▼
    inputResolver (in managedinput)
    ├── catalogerName: "javascript-lock-cataloger"
    └── sourcePaths: [workdir/package.json, workdir/<lock>]
```