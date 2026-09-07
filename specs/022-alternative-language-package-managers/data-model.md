# Data Model: Alternative Language Package Managers

## Package directive

The existing `PackagesDirective` remains the unit of configuration and execution.

| Field | Type | Required | Semantics |
|---|---|---:|---|
| `Type` | `PackagesDirectiveType` | yes | One of the existing package types. Alternative types are `javascript-yarn`, `javascript-pnpm`, `python-uv`, and `python-poetry`. |
| `FileBased.Workdir` | string | yes for file-based directives | Container directory containing the manifest and lock file. |
| `FileBased.Spec` | string | yes for file-based directives | Manifest path, defaulted by the ecosystem registry. |
| `FileBased.Lock` | string | ecosystem-dependent | Lock path, defaulted by the ecosystem registry. |
| `FileBased.Version` | string | yes for alternative types; forbidden for other types | Exact alternative-manager version in `X.Y.Z` form. |
| `Env` | map[string]string | no | Existing per-directive environment variables. |
| `isAlternativeManager(type)` | switch helper | all directive types | Returns true only for Yarn, pnpm, uv, and Poetry; used for version validation and alternative-manager command selection. |
| `PackageCommandWrapper` | internal factory/type | file-based ecosystems | Centralizes `cd` and environment-prefix composition and returns an install-command function. For alternative types it creates an ephemeral scope, selects the isolated executable, and associates cleanup with the generated command. |
| `Spec.Packages` | []string | only for `os-pm` | Existing inline OS package list; unchanged by this feature. |

## Package command wrapper

`PackageEcosystem` keeps its existing `InstallCmd` field. A new internal `PackageCommandWrapper` factory returns that function shape and centralizes the repeated shell composition:

```go
type PackageCommandWrapper struct {
    // manager-specific wrapper configuration
}

func (w PackageCommandWrapper) InstallCmd(...) string
```

The wrapper adds `cd` and sorted environment assignments for every file-based command. For the four alternative types selected by the switch helper, it creates an ephemeral ecosystem-specific scope, invokes the isolated executable, and runs the associated cleanup command only after successful dependency installation. Primary and unrelated types use the same wrapper without an ephemeral manager scope.

## Supported alternative-manager mapping

| Directive type | Manager | Bootstrap tool | Isolated bootstrap form | Existing install command |
|---|---|---|---|---|
| `javascript-yarn` | Yarn | npm | `npm install --global --prefix <prefix> yarn@<version>`; invoke `<prefix>/bin/yarn` | `yarn install --frozen-lockfile` |
| `javascript-pnpm` | pnpm | npm | `npm install --global --prefix <prefix> pnpm@<version>`; invoke `<prefix>/bin/pnpm` | `pnpm install --frozen-lockfile` |
| `python-uv` | uv | pip in venv | `python3 -m venv <venv>` then `<venv>/bin/python -m pip install uv==<version>`; invoke `<venv>/bin/uv` | `uv sync --frozen` |
| `python-poetry` | Poetry | pip in venv | `python3 -m venv <venv>` then `<venv>/bin/python -m pip install poetry==<version>`; invoke `<venv>/bin/poetry` | `poetry sync --no-root` |

## Lifecycle state

Each alternative directive has an independent logical lifecycle:

`Configured` → `AlternativeAbsent` → `ScopedBootstrapComplete` → `DependenciesInstalled` → `TemporaryScopeRemoved`.

Failure transitions stop at the failing state and return an error with the operation context:

- bootstrap/version resolution failure: no dependency command runs;
- dependency/lock failure: original install failure is returned and successful-install cleanup does not run;
- cleanup failure: the build fails after dependency installation;
- pre-existing manager: configuration/build command fails before bootstrap and dependency installation.

## Invariants

- Alternative directives require a non-empty exact `X.Y.Z` version.
- Primary `javascript-npm` and `python-pip` directives do not use `Version` and generate their current commands.
- A pre-existing alternative-manager executable is invalid for the builder image.
- The switch helper identifies exactly the four supported alternative types; no registry boolean is required.
- The command wrapper installs the alternative manager only in a unique directive-local npm prefix or Python venv and removes only that ephemeral scope; it may not delete files belonging to another directive or pre-existing image state.
- Manifest, lock, installed dependency, and SBOM source paths remain unchanged.
