# YAML Config Schema Contract: `packages[].env`

## Specification

The `packages` array entry gains an optional `env` field:

```yaml
packages:
  - type: os-pm
    spec:
      - curl
    env:                            # NEW: optional map[string]string
      DOCKER_CONFIG: /run/secrets/docker-config
```

## Schema

```yaml
env:
  type: object
  required: false
  description: >
    Environment variables to pass to the package manager process.
    Accepted in config schema for all package types, but runtime
    behavior is only implemented for type `os-pm`. Other types
    silently ignore this field.
  patternProperties:
    "^[a-zA-Z_][a-zA-Z0-9_]*$":
      type: string
      description: >
        The value of the environment variable. Empty strings are allowed.
        Values may reference paths mounted via the `secrets` directive
        (e.g., `/run/secrets/TOKEN`).
  additionalProperties: false
```

## Validation Errors

| Condition | Error Message |
|-----------|---------------|
| Invalid env var name | `invalid environment variable name %q in packages[%d].env: must match POSIX naming pattern [a-zA-Z_][a-zA-Z0-9_]*` |
| Non-string value (YAML) | Handled by Go YAML unmarshaler automatically — `map[string]string` type rejects non-string values |
| Empty env map (`{}`) | Treated identically to no `env` — backward compatible |

## Backward Compatibility

- Existing `werf.yaml` files without `env` — **no change**
- Files with `env: {}` — **no change** (empty export, same as no env vars)
- Files with `env` on non-`os-pm` types — **parsed but silently ignored at runtime**
- The `env` field does not affect `imageSpec.config.env` — they serve different purposes
