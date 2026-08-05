# Research: JavaScript Package Ecosystems for werf Packages Directive

## Phase 0 Research

No [NEEDS CLARIFICATION] markers were present in the spec. This research documents the decisions made based on Syft documentation and existing patterns.

## Syft JavaScript Cataloger Analysis

### Source: [Anchore Syft Documentation — JavaScript](https://oss.anchore.com/docs/capabilities/javascript/#package-analysis)

### Catalogers

| Cataloger | Scans | Dependency Depth |
|-----------|-------|-----------------|
| `javascript-lock-cataloger` | `pnpm-lock.yaml`, `yarn.lock`, `package-lock.json` | Transitive |
| `javascript-package-cataloger` | `package.json` | Direct |

### Key Findings

1. **Single lock cataloger for all three formats** — Syft's `javascript-lock-cataloger` handles all three lock file formats (`package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`). This means all three JavaScript types share the same cataloger name but with different source paths.

2. **Package cataloger always included** — `javascript-package-cataloger` scans `package.json` for direct dependency metadata. All three JavaScript types use the same manifest file name (`package.json`), so the package cataloger configuration is identical for all three.

3. **Syft configuration options** — Syft exposes `javascript.include-dev-dependencies` (default: true), `javascript.npm-base-url`, and `javascript.search-remote-licenses`. These are syft-level configuration options and do not require werf-level changes. The default behavior (dev dependencies included) is acceptable for SBOM completeness.

### Decision: Dev dependencies included by default

- **Rationale**: Syft includes dev dependencies by default. This is consistent with the Python and Rust behaviors where all declared dependencies are included. Users who need to exclude dev dependencies can configure syft directly.
- **Alternatives considered**: Excluding dev dependencies by default would hide information from the SBOM and would be inconsistent with the "catalog everything" approach of the existing ecosystems.

## Package Manager Command Analysis

### npm

| Aspect | Detail |
|--------|--------|
| **Install command** | `npm ci` |
| **Lock file** | `package-lock.json` |
| **Frozen lock flag** | `npm ci` inherently uses `package-lock.json` and fails if missing or out of sync |
| **Why not `npm install`** | `npm install` allows lock file updates and may produce non-deterministic results in CI |

### Yarn

| Aspect | Detail |
|--------|--------|
| **Install command** | `yarn install --frozen-lockfile` |
| **Lock file** | `yarn.lock` |
| **Frozen lock flag** | `--frozen-lockfile` |
| **Why not `yarn install --frozen`** | `--frozen` is an alias for `--frozen-lockfile` in yarn v1, but `--frozen-lockfile` is more explicit and universally supported |

### pnpm

| Aspect | Detail |
|--------|--------|
| **Install command** | `pnpm install --frozen-lockfile` |
| **Lock file** | `pnpm-lock.yaml` |
| **Frozen lock flag** | `--frozen-lockfile` |
| **Why not `pnpm install`** | Without `--frozen-lockfile`, pnpm may update the lock file, which is undesirable in CI/CD |

## Ecosystem Registry Pattern (from existing codebase)

The existing `ecosystems` map in `pkg/config/packages_directive.go` registers each type with:

```go
type PackageEcosystem struct {
    Type          PackagesDirectiveType
    DefaultSpec   string
    DefaultLock   string
    InstallCmd    func(workdir, spec string) string
    CatalogerName string
}
```

For JavaScript, the entries will be:

| Type | DefaultSpec | DefaultLock | InstallCmd | CatalogerName |
|------|-------------|-------------|------------|---------------|
| `javascript-npm` | `package.json` | `package-lock.json` | `cd "<workdir>" && npm ci` | `javascript-lock-cataloger` |
| `javascript-yarn` | `package.json` | `yarn.lock` | `cd "<workdir>" && yarn install --frozen-lockfile` | `javascript-lock-cataloger` |
| `javascript-pnpm` | `package.json` | `pnpm-lock.yaml` | `cd "<workdir>" && pnpm install --frozen-lockfile` | `javascript-lock-cataloger` |

## Additional Research: Managed Input (SBOM filtering)

The `buildResolvers()` function in `pkg/sbom/managedinput/managedinput.go` dynamically constructs `inputResolver` entries from `config.Ecosystems()`. Each resolver maps:

- `inputType` → ecosystem type constant
- `catalogerName` → ecosystem's `CatalogerName`
- `sourcePaths` → `[workdir/spec, workdir/lock]` (only spec if lock is empty)
- `workdir` → `workdir` from the directive

For JavaScript types, all three use `javascript-lock-cataloger` as the cataloger name. The `buildResolvers()` function generates one resolver entry per type, so there will be three separate resolver entries — one for each JavaScript type. Each entry will have a different lock file path, but all will share the same cataloger name (`javascript-lock-cataloger`).

This is fine because:
1. `inputResolver` does not require unique cataloger names
2. `ToCatalogers()` iterates over directives and matches them to resolvers by `inputType`
3. Each directive's specific lock file path is set in the resolver's `sourcePaths` closure

## Documentation Research

The existing documentation in `docs/_data/werf_yaml.yml` lists types in the `type` field description. The current descriptions need to be updated to include the three new JavaScript types.

The `docs/pages_en/usage/build/stapel/instructions.md` and `docs/pages_ru/usage/build/stapel/instructions.md` have a "File-based package ecosystems" section with subsections for each ecosystem. New JavaScript subsections need to be added following the same pattern as the Rust Cargo section.