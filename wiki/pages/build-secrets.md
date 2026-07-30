---
title: Build Secrets
type: component
sources: S011
updated: 2026-07-30
---

# Build Secrets

werf supports three mutually exclusive secret types in `werf.yaml` — `env`, `src`, and `value`. They are defined under the `secrets:` directive on both [Stapel images](./os-pm-package-management.md) (shell/ansible builders) and Dockerfile images. (S011)

## Secret types

| Type | YAML key | Value source | ID default |
|------|----------|-------------|------------|
| Environment variable | `env` | An environment variable on the host | Falls back to the `env` name |
| File path | `src` | A file on the host filesystem | Falls back to `filepath.Base(src)` |
| Literal value | `value` | A plain string in `werf.yaml` | Required — no default |

At most one of `env`, `src`, or `value` may be set per secret entry. (S011 — `rawSecret.validate()`)

### Auto-ID

When `id` is omitted:

- `env` type → the `env` value becomes the `id`.
- `src` type → the base name of the `src` path becomes the `id`.
- `value` type → `id` is required; omitting it produces an error.

### Duplicate detection

All secret IDs in a single image must be unique. Duplicates are caught during config validation. (S011 — `GetValidatedSecrets()`)

## How secrets are mounted

The mounting strategy differs between Stapel and Dockerfile images.

### Stapel images (shell/ansible)

1. The secret is resolved to a temporary file on the host:
   - `env` → reads the env var value and writes it to a temp file.
   - `src` → uses the resolved absolute path of the source file directly.
   - `value` → writes the literal value to a temp file.
2. The temp file is mounted as a **read-only bind mount** into the build container at `/run/secrets/<id>`.
3. Inside the container, the secret is available at the path `/run/secrets/<id>`.

The mount path follows the pattern: `<host-path>:<container-path>:ro` where `<container-path>` is `/run/secrets/<id>`. (S011 — `generateMountPath()`)

### Dockerfile images

1. Each secret is converted to a BuildKit `--secret` argument string:
   - `env` → `id=<id>,env=<ENV_VAR_NAME>`
   - `src` → `id=<id>,src=<path>`
   - `value` → the literal value is exported as a temporary environment variable, then passed as `id=<id>,env=<TMP_ENV_KEY>`.
2. The secrets are passed to the Docker builder via `b.AppendSecrets(secret)`, which translates to BuildKit's `--secret` flag.
3. Inside the Dockerfile, secrets are accessed via `RUN --mount=type=secret,id=<id>`.

## Giterminism restrictions

Secrets are external dependencies. In strict giterminism mode (the default), each secret must be explicitly allowed in `werf-giterminism.yaml`:

- `env` secrets → allowed via `config.secrets.allowEnvVariables`.
- `src` secrets → allowed via `config.secrets.allowFiles`.
- `value` secrets → allowed via `config.secrets.allowValueIds`.

In loose giterminism mode (`--loose-giterminism`), all secrets are allowed without explicit configuration. (S011 — `config_secrets.go`)

## The `os-pm` env var fallback pattern

For `os-pm` packages, the `PACKAGES_VERSION` and `REGISTRY` environment variables are generated with a shell fallback template:

```bash
VAR="${VAR:-$(cat /run/secrets/VAR 2>/dev/null || true)}"
```

This means the variable takes its value from:
1. The environment variable `VAR` if set, OR
2. The content of `/run/secrets/VAR` if the file exists, OR
3. An empty string if neither is available.

This pattern pairs naturally with the `secrets:` directive: when a secret with `id: PACKAGES_VERSION` (or `id: REGISTRY`) is defined, it is mounted at `/run/secrets/PACKAGES_VERSION` (or `/run/secrets/REGISTRY`), and the `os-pm` install command automatically picks it up as a fallback. (S011 — `packages_commands.go`)

## `env:` under `packages:` is not currently supported

The `env:` directive under `packages:` in `werf.yaml` (e.g., `DOCKER_CONFIG: /run/secrets/`) is **not** a currently implemented feature. The `PackagesDirective` struct has no such field, and the raw YAML parser would flag it as an unsupported attribute. This is a target/future solution, not something that works today.

To pass environment variables to package manager commands, use the `imageSpec.config.env` at the image level or rely on the built-in `/run/secrets/` fallback pattern described above.