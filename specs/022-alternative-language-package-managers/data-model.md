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
| `Spec.Packages` | []string | only for `os-pm` | Existing inline OS package list; unchanged by this feature. |

## Supported alternative-manager mapping

| Directive type | Manager | Bootstrap tool | Bootstrap package/version form | Existing install command |
|---|---|---|---|---|
| `javascript-yarn` | Yarn | npm | `yarn@<version>` | `yarn install --frozen-lockfile` |
| `javascript-pnpm` | pnpm | npm | `pnpm@<version>` | `pnpm install --frozen-lockfile` |
| `python-uv` | uv | pip | `uv==<version>` | `uv sync --frozen` |
| `python-poetry` | Poetry | pip | `poetry==<version>` | `poetry sync --no-root` |

## Lifecycle state

Each alternative directive has an independent logical lifecycle:

`Configured` → `AlternativeAbsent` → `Bootstrapped` → `DependenciesInstalled` → `AlternativeRemoved`.

Failure transitions stop at the failing state and return an error with the operation context:

- bootstrap/version resolution failure: no dependency command runs;
- dependency/lock failure: original install failure is returned and successful-install cleanup does not run;
- cleanup failure: the build fails after dependency installation;
- pre-existing manager: configuration/build command fails before bootstrap and dependency installation.

## Invariants

- Alternative directives require a non-empty exact `X.Y.Z` version.
- Primary `javascript-npm` and `python-pip` directives do not use `Version` and generate their current commands.
- A pre-existing alternative-manager executable is invalid for the builder image.
- Cleanup is directive-local and may not delete files belonging to another directive or pre-existing image state.
- Manifest, lock, installed dependency, and SBOM source paths remain unchanged.
