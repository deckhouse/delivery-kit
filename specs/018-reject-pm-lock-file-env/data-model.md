# Data Model: reject PM_LOCK_FILE override

## PackagesDirective

Existing configuration entity in `pkg/config` representing one `packages` entry.

| Field | Type | Meaning | Validation impact |
|---|---|---|---|
| `Type` | `PackagesDirectiveType` | Package ecosystem, including `os-pm` | The new rule applies only when this is `os-pm`. |
| `Spec.Packages` | `[]string` | Inline package names for `os-pm` | Existing non-empty requirement remains unchanged. |
| `Env` | `map[string]string` | Environment declarations passed to package installation | For `os-pm`, the key `PM_LOCK_FILE` is prohibited regardless of value. Other keys retain existing behavior. |
| `FileBased` | `FileBasedSpec` | Workdir/spec/lock for file-based ecosystems | Not used by `os-pm`; existing validation remains unchanged. |

## PM_LOCK_FILE

A prohibited environment-key declaration for `os-pm`.

- Presence is invalid even when the value is empty or equals the supported default path.
- The value is not inspected after presence is detected.
- The error must name `PM_LOCK_FILE` and identify `/var/lib/pm/index.json` as the required SBOM source path.

## PM runtime index

The fixed in-image state file used by the `pm` SBOM cataloger.

- Path: `metadata.ContainerFactoryIndexPath` (`/var/lib/pm/index.json`).
- There is no configuration-supported path transition.
- Accepted `os-pm` directives continue to generate the existing installation command and SBOM collection continues to use this path.

## Validation transition

`rawPackagesDirective` YAML input → `PackagesDirective` conversion → `PackagesDirective.validate`:

- If type is `os-pm` and `Env` contains `PM_LOCK_FILE`: return an actionable configuration error.
- Otherwise: continue existing validation and return the directive.
- The error occurs before package command generation and build execution.
