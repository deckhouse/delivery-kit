# Contract: Ecosystem Registry for JavaScript Package Types

## Contract Type

In-code Go registry contract — the `ecosystems` map in `pkg/config/packages_directive.go`.

## Contract

Each JavaScript type registers a `PackageEcosystem` entry in the `ecosystems` map:

```go
var ecosystems = map[PackagesDirectiveType]PackageEcosystem{
    // ... existing entries ...

    PackagesDirectiveTypeJavaScriptNpm: {
        Type:          PackagesDirectiveTypeJavaScriptNpm,
        DefaultSpec:   "package.json",
        DefaultLock:   "package-lock.json",
        InstallCmd:    func(workdir, _ string) string { return fmt.Sprintf("cd %q && npm ci", workdir) },
        CatalogerName: "javascript-lock-cataloger",
    },
    PackagesDirectiveTypeJavaScriptYarn: {
        Type:          PackagesDirectiveTypeJavaScriptYarn,
        DefaultSpec:   "package.json",
        DefaultLock:   "yarn.lock",
        InstallCmd:    func(workdir, _ string) string { return fmt.Sprintf("cd %q && yarn install --frozen-lockfile", workdir) },
        CatalogerName: "javascript-lock-cataloger",
    },
    PackagesDirectiveTypeJavaScriptPnpm: {
        Type:          PackagesDirectiveTypeJavaScriptPnpm,
        DefaultSpec:   "package.json",
        DefaultLock:   "pnpm-lock.yaml",
        InstallCmd:    func(workdir, _ string) string { return fmt.Sprintf("cd %q && pnpm install --frozen-lockfile", workdir) },
        CatalogerName: "javascript-lock-cataloger",
    },
}
```

## Contract Semantics

### `InstallCmd` function

| Type | Command | Notes |
|------|---------|-------|
| `javascript-npm` | `cd "<workdir>" && npm ci` | Uses `npm ci` (not `npm install`) for deterministic CI installs |
| `javascript-yarn` | `cd "<workdir>" && yarn install --frozen-lockfile` | `--frozen-lockfile` ensures lock file consistency |
| `javascript-pnpm` | `cd "<workdir>" && pnpm install --frozen-lockfile` | `--frozen-lockfile` ensures lock file consistency |

All commands ignore the `spec` parameter (second argument to `InstallCmd`) — the spec file is used only for SBOM cataloger source paths, not for the install command.

### `CatalogerName` mapping

All three JavaScript types use `javascript-lock-cataloger` (for lock file scanning) and `javascript-package-cataloger` (for package.json scanning). The `CatalogerName` field in the registry maps to `javascript-lock-cataloger` for transitive dependency scanning. The `javascript-package-cataloger` is automatically applied by the `buildResolvers()` function because it includes `package.json` (the `DefaultSpec`) in the source paths.

### `buildResolvers` behavior

The existing `buildResolvers()` in `pkg/sbom/managedinput/managedinput.go` iterates over `config.Ecosystems()` and creates one `inputResolver` per type. For JavaScript types:

```go
inputResolver{
    inputType:     PackagesDirectiveTypeJavaScriptNpm,  // or Yarn/Pnpm
    catalogerName: "javascript-lock-cataloger",
    filterMode:    scanner.CatalogerFilterExactPath,
    sourcePaths: func(d *config.PackagesDirective) []string {
        return []string{
            path.Join(d.FileBased.Workdir, d.FileBased.Spec),     // package.json
            path.Join(d.FileBased.Workdir, d.FileBased.Lock),     // lock file
        }
    },
    workdir: func(d *config.PackagesDirective) string {
        return d.FileBased.Workdir
    },
}
```

## Interface Compliance

This contract is implemented by the `PackageEcosystem` struct and the `Ecosystems()` function. No new interfaces are introduced. The existing compile-time checks remain sufficient.

## Example: Generated Commands

```go
// For packages: [{type: javascript-npm, workdir: /app}, {type: javascript-yarn, workdir: /app/web}]

GeneratePackagesCommands(packages) -> []string{
    `cd "/app" && npm ci`,
    `cd "/app/web" && yarn install --frozen-lockfile`,
}
```

## Example: Generated Catalogers

```go
// For packages: [{type: javascript-pnpm, workdir: /app/packages/sdk}]

ToCatalogers(packages) -> []scanner.Cataloger{
    {
        Name:        "javascript-lock-cataloger",
        FilterMode:  CatalogerFilterExactPath,
        SourcePaths: []string{"/app/packages/sdk/package.json", "/app/packages/sdk/pnpm-lock.yaml"},
        Workdir:     "/app/packages/sdk",
    },
}
```