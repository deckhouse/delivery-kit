# Data Model: Generalize Package Secret References

## Build secret

An existing validated `config.Secret` declaration mounted for the build stage.

| Field | Type | Rules |
|---|---|---|
| `Id` | string | Unique within the image's declared secrets; identifies the mount at `/run/secrets/<Id>`. |
| `ValueFromEnv` | string | Optional source selector for an environment-backed secret. |
| `ValueFromSrc` | string | Optional source selector for a file-backed secret. |
| `ValueFromPlain` | string | Optional literal secret value. |

The feature uses only the set of declared `Id` values during package command generation. Secret source values are not passed to the generator.

## Package environment entry

An existing `packages.env` map entry.

| Field | Type | Rules |
|---|---|---|
| Name | string | Existing POSIX environment variable name validation applies. |
| Value | string | Either an ordinary literal or an exact `/run/secrets/<secret-id>` reference. `${VARIABLE}` text is literal. |

An exact reference must identify a declared build secret. The reference is not expanded when it is only a substring of a larger value.

## Secret reference

A derived interpretation of a package environment value.

| Field | Type | Rules |
|---|---|---|
| Mounted path | string | Exact `/run/secrets/<secret-id>` value. |
| Secret ID | string | Must correspond to a declared build secret. |
| Resolution time | stage runtime | Read from the read-only mount immediately before the package manager runs. |

Undeclared references and declared secrets whose configured sources cannot be resolved fail during configuration parsing, before a build stage or package manager starts. Empty configured values remain valid and resolve to an empty value.

## Resolved package environment

The ephemeral environment passed to a package-manager command.

| Property | Behavior |
|---|---|
| Ordinary value | Preserved using the existing shell-quoting and sorted serialization. |
| Secret reference | Read from its mounted file without embedding the content in generated command text. |
| Existing same-name environment value | Overridden by an explicit secret reference. |
| Lifetime | Package-stage process and descendants only. |
| Command shape | Single-line inline assignment: `ENV_VAR=value command`. |
| Persistence | Must not become image environment, command metadata, cache identity, SBOM data, or a build artifact. |

## Compatibility state

`PACKAGES_VERSION` retains its existing required provenance behavior when no explicit `packages.env` secret reference supplies it: the package command writes the resolved value to `metadata.ContainerFactoryVersionPath`. `REGISTRY` remains compatible for existing package configurations, but its secret resolution shares the generic reference-reading primitive rather than adding another variable-specific expansion mechanism.

## State transitions

```text
packages.env literal
  -> serialized unchanged

packages.env exact secret path
  -> declared-ID validation during parsing
  -> configured-source validation during parsing
  -> single-line inline environment assignment
  -> mounted-value read in package stage
  -> package manager

invalid or configuration-unresolvable exact reference
  -> actionable parsing failure
  -> build stage not created
```
