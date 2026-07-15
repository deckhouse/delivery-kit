---
status: migrated
feature: python-packages
created: 2026-07-10
source: branch feat-sbom-get-python-sbom
---

# Python Package Ecosystems for werf Packages Directive

## Clarifications

### Session 2026-07-15

- Q: Should alias support (`uv`, `pip`, `poetry` as short types) be kept? → A: No, remove alias support from the specification.

## User Scenarios

### Scenario: Declare uv-managed Python dependencies

A user has a Python project managed by **uv** with a `pyproject.toml` and `uv.lock`. They add a `packages` directive in `werf.yaml`:

```yaml
packages:
  - type: python-uv
    workdir: /app
```

- **WHEN** the build runs
- **THEN** werf runs `cd "/app" && uv sync --frozen` inside the build container, installing locked dependencies
- **AND** `--frozen` ensures the build fails if `uv.lock` is missing or outdated
- **AND** syft's `python-package-cataloger` scans `/app/pyproject.toml` and `/app/uv.lock` to produce the SBOM
- **AND** SBOM filtering keeps only components found by those declared paths

### Scenario: Declare pip-managed Python dependencies

A user has a `requirements.txt` file without a lock mechanism. They use:

```yaml
packages:
  - type: python-pip
    workdir: /app
```

- **WHEN** the build runs
- **THEN** werf runs `cd "/app" && pip install --no-cache-dir -r "requirements.txt"` inside the build container
- **AND** the `lock` field is rejected by config validation (pip has no lock semantics)
- **AND** syft's `python-package-cataloger` scans `/app/requirements.txt` for the SBOM

### Scenario: Declare poetry-managed Python dependencies

A user has a project managed by **poetry** with `pyproject.toml` and `poetry.lock`:

```yaml
packages:
  - type: python-poetry
    workdir: /app
```

- **WHEN** the build runs
- **THEN** werf runs `cd "/app" && poetry sync` inside the build container
- **AND** syft's `python-package-cataloger` scans `/app/pyproject.toml` and `/app/poetry.lock` for the SBOM

### Scenario: Mix Python ecosystems with other package types

A project uses both Go modules and Python dependencies:

```yaml
packages:
  - type: go-mod
    workdir: /app
  - type: python-uv
    workdir: /lib
  - type: os-pm
    packages:
      - curl
```

- **WHEN** the build runs
- **THEN** all three directives produce commands that are run inside the build container: `go mod download`, `uv sync --frozen`, `pm install curl`
- **AND** each directive contributes its own cataloger for SBOM scanning

## Requirements

### R1: Three Python ecosystem types

The `packages` directive SHALL support types `python-uv`, `python-pip`, and `python-poetry`, each with its own package manager command, default manifest file, and cataloger.

### R3: File-based ecosystem abstraction

All file-based package ecosystems (Go modules, Python types) SHALL use a shared `FileBasedSpec` with `Workdir`, `Spec`, and `Lock` fields. The old `GoModSpec` SHALL be removed.

### R4: Ecosystem registry

All file-based ecosystems SHALL be registered in a single `ecosystems` map keyed by `PackagesDirectiveType`. The map SHALL be exposed read-only via `Ecosystems()`.

### R5: Command generation from registry

`GeneratePackagesCommands` SHALL dispatch commands via the ecosystem registry rather than a hardcoded switch. The `PackagesDirectiveTypeOSPM` case remains special because it has a different structure.

### R6: SBOM catalogers from ecosystem registry

`ToCatalogers` and `buildResolvers` in `pkg/sbom/managedinput` SHALL derive cataloger entries dynamically from `config.Ecosystems()` instead of hardcoding them per type.

### R7: Lock validation (determinism)

- For `python-uv`: `uv sync --frozen` SHALL be used, ensuring `uv.lock` exists and is in sync
- For `python-poetry`: `poetry sync` SHALL be used, ensuring `poetry.lock` exists and is in sync
- For `python-pip`: the `lock` field in YAML SHALL be rejected at config validation (pip has no lock semantics)

### R8: Default file names

| Type | Default spec | Default lock |
|------|-------------|--------------|
| `python-uv` | `pyproject.toml` | `uv.lock` |
| `python-pip` | `requirements.txt` | (empty) |
| `python-poetry` | `pyproject.toml` | `poetry.lock` |
| `go-mod` | `go.mod` | `go.sum` |

### R9: Install commands

| Type | Command |
|------|---------|
| `python-uv` | `uv sync --frozen` |
| `python-pip` | `pip install --no-cache-dir -r <spec>` |
| `python-poetry` | `poetry sync` |
| `go-mod` | `go mod download` |

## Success Criteria

- SC1: A `packages` entry with `type: python-uv` and `workdir: /app` successfully installs dependencies and generates an SBOM containing `requests@2.32.3` when `uv.lock` lists that dependency.
- SC2: A `packages` entry with `type: python-pip` and `workdir: /app` successfully installs dependencies and generates an SBOM containing `requests@2.32.3` when `requirements.txt` lists that dependency.
- SC3: A `packages` entry with `type: python-poetry` and `workdir: /app` successfully installs dependencies and generates an SBOM containing `requests@2.32.3` when `poetry.lock` lists that dependency.
- SC4: `python-pip` rejects the `lock` field at config validation.
- SC5: An unknown package type (e.g., `pythonn-uv`) is rejected at config validation.
- SC6: A `python-uv` entry without `workdir` is rejected at config validation.
- SC7: A mixed configuration (`go-mod` + `python-uv` + `os-pm`) generates all expected commands and catalogers correctly.

## Assumptions

- Python package managers (`uv`, `pip`, `poetry`) must be pre-installed in the builder image; werf does not install them.
- The lock file is expected to be present in the build context by the respective package manager. For `uv`, `uv sync --frozen` enforces this. For `poetry`, `poetry sync` enforces lock file consistency. For `pip`, no lock file is used.
- `pip` has no lock semantics; users are expected to pin versions in `requirements.txt` directly.