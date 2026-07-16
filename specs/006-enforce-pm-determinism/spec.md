---
status: migrated
feature: enforce-pm-determinism
created: 2026-07-16
source: branch feat/config/enforce-pm-determinism
---

# Enforce os-pm Determinism via Spec+Lock Files

## User Scenarios

### Scenario: Declare os-pm-managed system packages with spec+lock files

A user has a dependency on OS-level packages (`curl`, `jq`, etc.) managed via a Container Factory `pm` tool. They declare the dependencies in a `pm.yaml` spec file and lock them in a `pm.lock` file. In `werf.yaml` they add:

```yaml
packages:
  - type: os-pm
    workdir: /
```

- **WHEN** the build runs
- **THEN** werf runs `pm sync --from /pm.lock` inside the build container, installing exactly the locked package versions
- **AND** the lock file (`pm.lock`) contains pinned versions with integrity hashes for deterministic, reproducible builds
- **AND** the `pm lock` command (run outside werf, during development) resolves `pm.yaml` and writes `pm.lock`
- **AND** SBOM components are read from `pm.lock` rather than from a runtime query of installed packages

### Scenario: Override default spec/lock filenames

A user has custom filenames for their PM spec and lock files:

```yaml
packages:
  - type: os-pm
    workdir: /app
    spec: custom-pm.yaml
    lock: custom-pm.lock
```

- **WHEN** the build runs
- **THEN** werf runs `pm sync --from /app/custom-pm.lock` using the user-specified lock filename
- **AND** syft's cataloger scans `/app/custom-pm.yaml` and `/app/custom-pm.lock` for the SBOM

### Scenario: No packages directive

A user does not need any OS-level packages:

- **WHEN** the build runs
- **THEN** no `pm sync` command is generated
- **AND** no os-pm SBOM processing occurs
- **AND** the build behaves identically to before the feature

## Requirements

### R1: File-based ecosystem registration

`os-pm` SHALL be registered in the `ecosystems` registry (alongside `go-mod`, `python-uv`, `rust-cargo`, etc.) with:
- `DefaultSpec: "pm.yaml"`
- `DefaultLock: "pm.lock"`
- Install command: `pm sync --from <workdir>/pm.lock`

### R2: Removal of flat package list model

The `PackagesSpec` struct with `Packages []string` SHALL be removed. The `normalizePackages()` function SHALL be removed.

### R3: Unified validation

All package types, including `os-pm`, SHALL validate using the same `FileBasedSpec` rules: `workdir` is required, `spec` is required. The `os-pm`-specific validation branch SHALL be removed.

### R4: Unified YAML parsing

`fillOSPMSpec()` SHALL be removed. `toDirective()` SHALL populate `FileBasedSpec` uniformly for all types via `fillFileBasedSpec()`.

### R5: Config `spec` field as string

The raw YAML `spec` field SHALL be a string (file path) for all package types, including `os-pm`. The old approach of `spec` being a string array for `os-pm` is no longer valid.

### R6: Deterministic install command

`GeneratePackagesCommands` SHALL produce a single `pm sync --from <workdir>/pm.lock` command per `os-pm` directive, instead of multiple `pm install <pkg>` commands. The container factory version snapshot command SHALL be emitted once before the first `os-pm` install command, same as before.

### R7: SBOM collection from lock file

`CollectBOM` in `pkg/sbom/packages/os_pm/` SHALL read `pm.lock` from inside the built container and parse its `{"metadata":..., "packages":{...}}` envelope. The parser SHALL be renamed from `ParsePmInstalledJSON` to `ParsePmLockJSON`. The `packages` object within the lock file contains the `pm info --installed --json` data pre-recorded at development time.

### R8: Lock path propagation

The build phase SHALL pass the concrete lock file path (computed from `workdir` + `lock`) instead of a boolean. `HasOSPMPackages()` → `OSPMLockPath()` returning the full path `<workdir>/<lock>`.

### R9: SBOM managed input dynamic resolution

`buildResolvers` in `pkg/sbom/managedinput` SHALL derive catalogers from `config.Ecosystems()`. With `os-pm` in the registry, it automatically gets a cataloger whose source paths include both `Workdir/Spec` and `Workdir/Lock`.

### R10: Defaults for spec/lock

When `spec` is omitted, `pm.yaml` SHALL be used as default. When `lock` is omitted, `pm.lock` SHALL be used as default. Wildcard/custom `spec` SHALL be allowed.

## Success Criteria

- **SC1**: An `os-pm` directive with `workdir: /` generates the command `pm sync --from /pm.lock` (preceded by the container factory version snapshot command).
- **SC2**: An `os-pm` directive with `workdir: /app` generates the command `pm sync --from /app/pm.lock`.
- **SC3**: Custom `spec` and `lock` values are respected in both the install command and SBOM cataloger source paths.
- **SC4**: An `os-pm` directive without `workdir` is rejected at config validation.
- **SC5**: An `os-pm` directive using the old `spec` as a list of strings is rejected at YAML unmarshal time.
- **SC6**: The SBOM generated from `pm.lock` contains all packages declared in the lock file with correct versions, licenses, dependencies, and hashes.
- **SC7**: A build without any `os-pm` directive produces no `pm sync` command and skips os-pm SBOM processing entirely.
- **SC8**: `ParsePmLockJSON` correctly parses the `{"metadata":..., "packages":{...}}` format and returns an empty map for an empty packages object.

## Assumptions

- The `pm` binary is pre-installed in the builder image; werf does not install or manage it.
- The `pm.yaml` spec file is authored by the user and committed to the repository alongside `pm.lock`.
- The `pm.lock` file is generated by `pm lock` (outside werf) and committed. It contains deterministic, pinned package versions.
- The container factory version file (`/var/lib/pm/version`) must be present in the builder image for SBOM purl generation.
