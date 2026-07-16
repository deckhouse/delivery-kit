# Quickstart: JavaScript Package Ecosystems Validation

## Prerequisites

- Go 1.24+
- `task` CLI
- Docker (for e2e tests)
- `npm`, `yarn`, `pnpm` (only needed if running e2e tests locally)

## Quick Validation

### 1. Build

```bash
task build
```

Expected: Binary builds successfully at `./bin/werf`.

### 2. Unit Tests — Config Parsing

```bash
task test:unit -- -run "TestConfig.*javascript|javascript" ./pkg/config/
```

Expected: All JavaScript config parsing tests pass:
- `javascript-npm` with only `workdir` defaults spec and lock
- `javascript-npm` with explicit spec and lock overrides
- Same for `javascript-yarn` and `javascript-pnpm`
- Missing `workdir` rejected
- Unknown type (e.g., `javascript-bower`) rejected
- Mix of JavaScript types with other ecosystem types

### 3. Unit Tests — SBOM Catalogers

```bash
task test:unit -- ./pkg/sbom/managedinput/
```

Expected: All SBOM cataloger tests pass:
- `ToCatalogers` returns correct cataloger entries for each JavaScript type
- `FilterBOMBySourcePaths` correctly filters BOM components by JavaScript source paths
- Mixed directive configurations produce correct cataloger combinations

### 4. Unit Tests — Command Generation

```bash
task test:unit -- -run "TestGeneratePackagesCommands" ./pkg/build/stage/
```

Expected: All command generation tests pass:
- `javascript-npm` generates `cd "<workdir>" && npm ci`
- `javascript-yarn` generates `cd "<workdir>" && yarn install --frozen-lockfile`
- `javascript-pnpm` generates `cd "<workdir>" && pnpm install --frozen-lockfile`
- Mixed directives generate correct combined commands

### 5. Full Unit Test Suite

```bash
task test:unit
```

Expected: All tests pass.

### 6. Linting

```bash
task lint:golangci-lint
```

Expected: No linting errors.

### 7. E2E Tests (requires Docker)

```bash
task test:e2e -- labelFilter="javascript"
```

Expected: All e2e tests pass:
- `npm_test.go`: Builds an image with `javascript-npm` directive, verifies SBOM contains expected packages
- `yarn_test.go`: Builds an image with `javascript-yarn` directive, verifies SBOM contains expected packages
- `pnpm_test.go`: Builds an image with `javascript-pnpm` directive, verifies SBOM contains expected packages

## Validation Matrix

| Scenario | Test | Expected Outcome |
|----------|------|-----------------|
| `javascript-npm` with defaults | Unit test | `package.json` + `package-lock.json` |
| `javascript-yarn` with defaults | Unit test | `package.json` + `yarn.lock` |
| `javascript-pnpm` with defaults | Unit test | `package.json` + `pnpm-lock.yaml` |
| Explicit spec/lock overrides | Unit test | Custom values used |
| Missing `workdir` | Unit test | Validation error |
| Unknown type | Unit test | `unsupported packages type` error |
| Mixed with `go-mod` + `os-pm` | Unit test | All commands generated correctly |
| Multiple JavaScript entries | Unit test | Separate commands + catalogers |
| npm install + SBOM | E2E test | SBOM contains `lodash@4.17.21` |
| yarn install + SBOM | E2E test | SBOM contains `lodash@4.17.21` |
| pnpm install + SBOM | E2E test | SBOM contains `lodash@4.17.21` |

## Data Model Reference

See [data-model.md](data-model.md) for the complete data model.

## Contract Reference

See [contracts/config-schema.md](contracts/config-schema.md) for the YAML config schema.
See [contracts/ecosystem-registry.md](contracts/ecosystem-registry.md) for the ecosystem registry contract.