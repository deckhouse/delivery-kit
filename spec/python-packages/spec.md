---
status: migrated
feature: python-packages
created: 2026-07-10
source: branch feat-sbom-get-python-sbom
---

# Python Package Ecosystems for werf Packages Directive

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
- **THEN** werf runs `cd "/app" && poetry install --no-root` inside the build container
- **AND** syft's `python-package-cataloger` scans `/app/pyproject.toml` and `/app/poetry.lock` for the SBOM

### Scenario: Use short aliases

A user prefers concise YAML:

```yaml
packages:
  - type: uv
    workdir: /app
```

- **WHEN** werf parses the config
- **THEN** the alias is canonicalized to `python-uv` via the `aliasToType` index
- **AND** all defaults (`pyproject.toml`, `uv.lock`, `uv sync --frozen`, `python-package-cataloger`) apply identically

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

### R2: Short aliases

Types `uv`, `pip`, and `poetry` SHALL be accepted as aliases and canonicalized to their full form at parse time.

### R3: File-based ecosystem abstraction

All file-based package ecosystems (Go modules, Python types) SHALL use a shared `FileBasedSpec` with `Workdir`, `Spec`, and `Lock` fields. The old `GoModSpec` SHALL be removed.

### R4: Ecosystem registry

All file-based ecosystems SHALL be registered in a single `ecosystems` map keyed by `PackagesDirectiveType`. The map SHALL be exposed read-only via `Ecosystems()`.

### R5: Command generation from registry

`GeneratePackagesCommands` SHALL dispatch commands via the ecosystem registry rather than a hardcoded switch. The `PackagesDirectiveTypeOSPM` case remains special because it has a different structure.

### R6: SBOM catalogers from ecosystem registry

`ToCatalogers` and `buildResolvers` in `pkg/sbom/managedinput` SHALL derive cataloger entries dynamically from `config.Ecosystems()` instead of hardcoding them per type.

### R7: Lock validation (determinism)

- For `python-uv`: `uv sync --frozen` SHALL be used, ensuring `uv.lock` exists
- For `python-poetry`: `poetry.lock` SHALL be the default lock file
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
| `python-poetry` | `poetry install --no-root` |
| `go-mod` | `go mod download` |

## Success Criteria

- SC1: A `packages` entry with `type: python-uv` (or alias `uv`) and `workdir: /app` successfully installs dependencies and generates an SBOM containing `requests@2.32.3` when `uv.lock` lists that dependency.
- SC2: A `packages` entry with `type: python-pip` (or alias `pip`) and `workdir: /app` successfully installs dependencies and generates an SBOM containing `requests@2.32.3` when `requirements.txt` lists that dependency.
- SC3: A `packages` entry with `type: python-poetry` (or alias `poetry`) and `workdir: /app` successfully installs dependencies and generates an SBOM containing `requests@2.32.3` when `poetry.lock` lists that dependency.
- SC4: `python-pip` rejects the `lock` field at config validation.
- SC5: An unknown package type (e.g., `pythonn-uv`) is rejected at config validation.
- SC6: A `python-uv` entry without `workdir` is rejected at config validation.
- SC7: A mixed configuration (`go-mod` + `python-uv` + `os-pm`) generates all expected commands and catalogers correctly.

## Assumptions

- Python package managers (`uv`, `pip`, `poetry`) must be pre-installed in the builder image; werf does not install them.
- The lock file is expected to be present in the build context by the respective package manager. For `uv`, the `--frozen` flag enforces this. For `poetry`, the lock file is expected but not enforced by a flag (the user must ensure it exists).
- `pip` has no lock semantics; users are expected to pin versions in `requirements.txt` directly.