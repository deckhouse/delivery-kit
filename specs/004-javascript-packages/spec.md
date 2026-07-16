---
status: draft
feature: javascript-packages
created: 2026-07-15
source:
---

# JavaScript Package Ecosystems for werf Packages Directive

## User Scenarios

### Scenario: Declare npm-managed JavaScript dependencies

A user has a JavaScript project managed by **npm** with a `package.json` and `package-lock.json`. They add a `packages` directive in `werf.yaml`:

```yaml
packages:
  - type: javascript-npm
    workdir: /app
```

- **WHEN** the build runs
- **THEN** werf runs `cd "/app" && npm ci` inside the build container, installing locked dependencies
- **AND** `npm ci` ensures the build fails if `package-lock.json` is missing or outdated
- **AND** syft's `javascript-lock-cataloger` scans `/app/package-lock.json` to produce the SBOM
- **AND** syft's `javascript-package-cataloger` scans `/app/package.json` for direct dependency metadata
- **AND** SBOM filtering keeps only components found by those declared paths

### Scenario: Declare yarn-managed JavaScript dependencies

A user has a JavaScript project managed by **Yarn** with a `package.json` and `yarn.lock`:

```yaml
packages:
  - type: javascript-yarn
    workdir: /app
```

- **WHEN** the build runs
- **THEN** werf runs `cd "/app" && yarn install --frozen-lockfile` inside the build container
- **AND** `--frozen-lockfile` ensures the build fails if `yarn.lock` is missing or out of sync
- **AND** syft's `javascript-lock-cataloger` scans `/app/yarn.lock` for the SBOM
- **AND** syft's `javascript-package-cataloger` scans `/app/package.json` for direct dependency metadata

### Scenario: Declare pnpm-managed JavaScript dependencies

A user has a JavaScript project managed by **pnpm** with a `package.json` and `pnpm-lock.yaml`:

```yaml
packages:
  - type: javascript-pnpm
    workdir: /app
```

- **WHEN** the build runs
- **THEN** werf runs `cd "/app" && pnpm install --frozen-lockfile` inside the build container
- **AND** `--frozen-lockfile` ensures the build fails if `pnpm-lock.yaml` is missing or out of sync
- **AND** syft's `javascript-lock-cataloger` scans `/app/pnpm-lock.yaml` for the SBOM
- **AND** syft's `javascript-package-cataloger` scans `/app/package.json` for direct dependency metadata

### Scenario: Mix JavaScript with other package types

A project uses both Go modules and npm dependencies:

```yaml
packages:
  - type: go-mod
    workdir: /app
  - type: javascript-npm
    workdir: /app/web
  - type: os-pm
    packages:
      - nodejs
```

- **WHEN** the build runs
- **THEN** all three directives produce commands that are run inside the build container: `go mod download`, `npm ci`, `pm install nodejs`
- **AND** each directive contributes its own cataloger for SBOM scanning

### Scenario: Multiple javascript entries in one image

A user has a monorepo with packages managed by different JavaScript package managers:

```yaml
packages:
  - type: javascript-npm
    workdir: /app
  - type: javascript-pnpm
    workdir: /app/packages/sdk
```

- **WHEN** the build runs
- **THEN** `npm ci` runs in `/app` and `pnpm install --frozen-lockfile` runs in `/app/packages/sdk`
- **AND** each entry produces separate `javascript-lock-cataloger` entries with their own lock file paths

## Requirements

### R1: Three JavaScript ecosystem types

The `packages` directive SHALL support types `javascript-npm`, `javascript-yarn`, and `javascript-pnpm`, each with its own package manager command, default manifest file, default lock file, and cataloger mapping.

### R2: Ecosystem registry integration

The `javascript-npm`, `javascript-yarn`, and `javascript-pnpm` types SHALL be registered in the existing `ecosystems` map keyed by `PackagesDirectiveType`. The types sit alongside `go-mod`, `python-uv`, `python-pip`, `python-poetry`, and `rust-cargo` — no new infrastructure is needed.

### R3: Command generation via registry

`GeneratePackagesCommands` SHALL dispatch JavaScript commands via the ecosystem registry:

| Type | Command |
|------|---------|
| `javascript-npm` | `npm ci` |
| `javascript-yarn` | `yarn install --frozen-lockfile` |
| `javascript-pnpm` | `pnpm install --frozen-lockfile` |

### R4: SBOM cataloger from ecosystem registry

`ToCatalogers` and `buildResolvers` in `pkg/sbom/managedinput` SHALL derive cataloger entries for JavaScript types from `config.Ecosystems()`. All three JavaScript types map to `javascript-lock-cataloger` with the respective lock file as source, and `javascript-package-cataloger` with `package.json` as source (for direct dependency metadata).

### R5: Lock validation (determinism)

- For `javascript-npm`: `npm ci` SHALL be used, which fails if `package-lock.json` is missing or out of sync
- For `javascript-yarn`: `yarn install --frozen-lockfile` SHALL be used, which fails if `yarn.lock` is missing or out of sync
- For `javascript-pnpm`: `pnpm install --frozen-lockfile` SHALL be used, which fails if `pnpm-lock.yaml` is missing or out of sync

### R6: Default file names

| Type | Default spec | Default lock |
|------|-------------|--------------|
| `javascript-npm` | `package.json` | `package-lock.json` |
| `javascript-yarn` | `package.json` | `yarn.lock` |
| `javascript-pnpm` | `package.json` | `pnpm-lock.yaml` |

### R7: Install commands

| Type | Command |
|------|---------|
| `javascript-npm` | `npm ci` |
| `javascript-yarn` | `yarn install --frozen-lockfile` |
| `javascript-pnpm` | `pnpm install --frozen-lockfile` |

### R8: Cataloger mapping

| Type | Lock cataloger | Package cataloger |
|------|---------------|-------------------|
| `javascript-npm` | `javascript-lock-cataloger` scanning `package-lock.json` | `javascript-package-cataloger` scanning `package.json` |
| `javascript-yarn` | `javascript-lock-cataloger` scanning `yarn.lock` | `javascript-package-cataloger` scanning `package.json` |
| `javascript-pnpm` | `javascript-lock-cataloger` scanning `pnpm-lock.yaml` | `javascript-package-cataloger` scanning `package.json` |

## Success Criteria

- SC1: A `packages` entry with `type: javascript-npm` and `workdir: /app` successfully installs dependencies and generates an SBOM containing `lodash@4.17.21` when `package-lock.json` lists that dependency.
- SC2: A `packages` entry with `type: javascript-yarn` and `workdir: /app` successfully installs dependencies and generates an SBOM containing `lodash@4.17.21` when `yarn.lock` lists that dependency.
- SC3: A `packages` entry with `type: javascript-pnpm` and `workdir: /app` successfully installs dependencies and generates an SBOM containing `lodash@4.17.21` when `pnpm-lock.yaml` lists that dependency.
- SC4: An unknown JavaScript package type (e.g., `javascript-bower`) is rejected at config validation.
- SC5: A `javascript-npm` entry without `workdir` is rejected at config validation.
- SC6: A mixed configuration (`go-mod` + `javascript-npm` + `os-pm`) generates all expected commands and catalogers correctly.
- SC7: Multiple `javascript-*` entries with different types and `workdir` values each produce correct install commands and separate cataloger entries (monorepo scenario).

## Assumptions

- JavaScript package managers (`npm`, `yarn`, `pnpm`) must be pre-installed in the builder image; werf does not install them.
- The lock file is expected to be present in the build context by the respective package manager. Each manager's frozen-lock-file flag enforces this.
- All three JavaScript types share `package.json` as the manifest/spec file. Syft's `javascript-package-cataloger` handles all three identically.
- `npm`, `yarn`, and `pnpm` are the three dominant JavaScript package managers; other tools (Bun, Deno) are out of scope for this specification.
- Dev dependencies are included in the SBOM by default (syft's default behavior). Users who wish to exclude them can configure syft via `javascript.include-dev-dependencies=false` at the syft level — werf does not need to expose this.