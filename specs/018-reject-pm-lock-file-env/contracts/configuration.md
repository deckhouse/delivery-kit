# Configuration Contract: `os-pm` environment

The user-facing configuration is a `packages` directive in `werf.yaml`/delivery-kit configuration:

```yaml
packages:
  - type: os-pm
    spec:
      - curl
    env:
      REGISTRY: registry.example.test
```

## Accepted

An `os-pm` directive is accepted when its `env` map does not contain `PM_LOCK_FILE`. Existing supported environment variables, such as registry-related variables, retain their current behavior.

## Rejected

Any declaration containing the exact key `PM_LOCK_FILE` is invalid:

```yaml
packages:
  - type: os-pm
    spec: [curl]
    env:
      PM_LOCK_FILE: /custom/index.json
```

This also applies to values `/var/lib/pm/index.json`, relative paths, and the empty string. Validation must fail before build/package installation starts. The error identifies `PM_LOCK_FILE` and states that the `pm` SBOM state must remain at `/var/lib/pm/index.json`.

The rule is scoped to `os-pm`; environment variables for other package types are not rejected by this feature.
