# Quickstart: Inline os-pm Syntax Validation Guide

**Date**: 2026-08-13 | **Branch**: `017-inline-os-pm-syntax-again`

## Prerequisites

- Go 1.24.10+
- Docker daemon running
- E2e test environment (already configured per constitution)
- `kind` cluster available (for e2e tests)

## Setup

No special setup is needed beyond cloning the repo and having the standard dev environment.

## Unit Tests — Scoped Validation

Run these in order to validate the core config parsing and command generation changes:

### 1. Config parsing — inline spec list

```bash
# Verify that os-pm accepts inline spec list and rejects file-based spec
task test:unit paths="./pkg/config/..." -- -focus="os-pm"
```

**Expected**: All os-pm tests pass with inline `spec: [curl, jq]` syntax.

**Key assertions**:
- `spec: ["curl", "jq"]` → `PackagesSpec{Packages: ["curl", "jq"]}` (not `FileBasedSpec`)
- `spec: "pm.yaml"` → rejected with validation error (SC-009)
- Empty `spec: []` → rejected (FR-003)
- `workdir: "/foo"` on os-pm → rejected (FR-004)
- `env: {REGISTRY: "..."}` → preserved in directive (FR-005)

### 2. Command generation — `pm install`

```bash
task test:unit paths="./pkg/config/..." -- -focus="commands"
```

**Expected**: Command generation tests assert `pm install curl==8.12.1 jq` instead of `pm sync --from pm.lock`.

**Key assertions**:
- Single os-pm section with 2 packages → `pm install curl==8.12.1 jq`
- Multiple os-pm sections → one `pm install` per section
- With `env` → required and user environment variables are prefixes on the same command as `pm install`
- The complete command contains no `; pm install` form, which would leave variables unexported
- Every env case compares the complete returned command with `Equal(expected)`, including preamble, env ordering, quoting, separators, and package arguments; no callback-based substring checks remain
- The command-generation implementation exposes readable prefix, env-prefix, install-command, and final-command stages
- Preamble (mkdir, version file) present in each command

### 3. SBOM collection — `ParsePmInstalledJSON`

```bash
task test:unit paths="./pkg/sbom/..." -- -focus="os-pm"
```

**Expected**: Tests pass with flat JSON format (no `{"packages": {...}}` wrapper).

**Key assertions**:
- `ParsePmInstalledJSON` parses the mandatory `/var/lib/pm/index.json` format; an absent index fails collection
- `ConvertToCycloneDX` produces correct CycloneDX components
- `containerFactoryVersion` is read from `/var/lib/pm/container-factory-version` inside the image; no host `PACKAGES_VERSION` fallback
- After successful version reading, the version value is written to debug logging
- Version-read errors are written to debug logging with image/path context
- No changes are made to `pkg/container_backend/docker_server_backend.go`

### 4. Stapel image config — `HasOSPMPackages`

```bash
task test:unit paths="./pkg/config/stapel_image_base_test.go"
```

**Expected**: Tests assert `HasOSPMPackages()` returns correct boolean.

### 5. Build stage — packages

```bash
task test:unit paths="./pkg/build/stage/..." -- -focus="os-pm"
```

**Expected**: Tests assert `pm install` command generation from stage integration.

### 6. All config tests

```bash
task test:unit paths="./pkg/config/..."
```

**Expected**: All tests pass — both os-pm and non-os-pm package types.

## Full Unit Suite

```bash
task test:unit
```

**Expected**: All unit tests pass across the entire project.

## E2E Tests — SBOM

```bash
task test:e2e paths="./test/e2e/sbom/..." labelFilter="os-pm"
```

**Expected**: SBOM e2e tests pass with inline os-pm syntax in fixtures.

### PURL resolver mixed-outcome regression

```bash
task test:e2e paths="./test/e2e/sbom/..." labelFilter="purl-resolver-errors"
```

**Expected**: the three-image build fails with an aggregated `resolve external references` error; failing image names and guaranteed failing components are listed, while the successful image is absent. The test must exercise a fresh SBOM path rather than a cache hit.

Before accepting the fixture, verify that every expected component is present in the built image. If `openssl` is not guaranteed by `Dockerfile.builder-base`, add it to the fixture package declaration or change the assertion to a guaranteed package.

```bash
task test:e2e paths="./test/e2e/sbom/..." labelFilter="packages"
```

**Expected**: All package-related SBOM e2e tests pass.

## Build Validation

```bash
task build
```

**Expected**: Binary compiles successfully without errors.

## Manual Inspection Points

### Verify `PMBOMPatcher` is gone

```bash
grep -r "PMBOMPatcher" pkg/sbom/
```

**Expected**: No references to `PMBOMPatcher` remain.

### Verify no obsolete os-pm lock workflow remains

```bash
grep -r "pm:lock\|pm.lock\|PMBOMPatcher" Taskfile.dist.yaml AGENTS.md pkg/config/ pkg/build/ pkg/sbom/
```

**Expected**: No `pm:lock` task, PMBOMPatcher, or os-pm lock-file source remains. Other package ecosystems may still use their own lock files.

### Verify SBOM-owned PM metadata and config cataloger wiring

```bash
`grep -R "InstalledPackagesIndexPath\|ContainerFactoryVersionDir\|ContainerFactoryVersionFile" pkg/sbom/os_pm/metadata pkg/sbom/packages/os_pm pkg/config/packages_commands.go`
```

**Expected**: `InstalledPackagesIndexPath`, `ContainerFactoryVersionDir`, and `ContainerFactoryVersionFile` are absent; `ContainerFactoryIndexPath`, `ContainerFactoryVersionPath`, and `CatalogerName` are defined only in `pkg/sbom/os_pm/metadata`, while config and SBOM code reference the shared values. `pkg/container_backend/docker_server_backend.go` is unchanged.

Run the ecosystem registration test:

```bash
task test:unit paths="./pkg/config/..." -- -focus="cataloger|ecosystem"
```

**Expected**: the os-pm `PackageEcosystem.CatalogerName` equals the shared metadata cataloger name, just as language ecosystem entries expose their cataloger names; the assertion fails if config uses an empty or duplicated literal. Dependency inspection must show that `pkg/config` does not import SBOM/container implementation code solely for metadata.

The version qualifier must be verified from the persisted image file, not from the host environment. Force a version-read error in the collector test and verify the debug log contains image/path context.

### Verify checksum test inputs

Inspect the checksum regression test and confirm that the compared cases use distinct inputs. A test that invokes the checksum function twice with identical arguments does not verify enabled/disabled behavior and must be replaced by a meaningful contract test or removed.

### Verify inline spec is the ONLY format for os-pm

```bash
grep -n "DefaultSpecFile.*pm.yaml" pkg/config/packages_directive.go
```

**Expected**: The `os-pm` ecosystem entry has `DefaultSpecFile: ""`.

## Validation Scenarios

### Scenario 1: Single os-pm section with multiple packages

**Given** a `werf.yaml` with:
```yaml
packages:
  - type: os-pm
    spec:
      - curl==8.12.1
      - jq
```

**Then**:
- Config parsing succeeds, `PackagesSpec.Packages = ["curl==8.12.1", "jq"]`
- `formatInstallCommand` generates the complete expected command string, including the preamble, env prefixes, separators, and `pm install curl==8.12.1 jq`
- Build stage runs the command
- SBOM contains both curl and jq from `/var/lib/pm/index.json`

### Scenario 2: Multiple os-pm sections

**Given** a `werf.yaml` with:
```yaml
packages:
  - type: os-pm
    spec:
      - curl==8.12.1
  - type: os-pm
    spec:
      - custom-pkg==2.0.0
    env:
      REGISTRY: internal-registry.example.com
```

**Then**:
- Two `pm install` commands are generated
- Second command has `REGISTRY=...` env prefix
- SBOM contains packages from both sections merged

### Scenario 3: No os-pm packages

**Given** a `werf.yaml` with no `packages` or non-os-pm packages only

**Then**:
- `HasOSPMPackages()` returns `false`
- No pm commands generated
- No os-pm SBOM processing

## Contract Verification

| Contract | File | Verification |
|----------|------|-------------|
| Config schema | `packages_directive.go` | `PackagesSpec.Packages []string` with inline list |
| Command generation | `packages_commands.go` | `formatInstallCommand` produces the complete expected command; tests use `Equal(expected)` rather than substring assertions |
| SBOM collection | `collect.go`, `pkg/sbom/os_pm/metadata/metadata.go` | metadata subpackage owns paths/cataloger name; collector integrates runtime BOM before generic patchers |
| Stapel interface | `stapel_image_base.go` | `HasOSPMPackages()` replaces `OSPMLockPath()` |
| Build phase | `sbom_step.go` | no inline os-pm merge and no os-pm checksum flag; package-level operation runs before PURL enrichment |
| Ecosystem registration | `packages_directive.go` | `CatalogerName` is passed from `pkg/sbom/os_pm/metadata` and covered by a config test |