---
title: "werf.yaml image configuration spec"
type: reference
sources: [S013]
updated: 2026-07-30
---

The `imageSpec` directive in `werf.yaml` configures the OCI image configuration spec — the image's metadata, environment variables, entrypoint, labels, and other properties. (S013)

## Global configuration

Set default configuration for all images via `build.imageSpec`:

```yaml
build:
  imageSpec:
    author: "Frontend Maintainer <frontend@example.com>"
    clearHistory: true
    config:
      labels:
        app: "my-app"
      removeLabels:
        - "unnecessary-label"
```

(S013)

> Global configuration does not apply to intermediate images (`final: false`). (S013)

## Per-image configuration

Override or extend the global configuration per image:

```yaml
image: frontend_image
from: alpine
imageSpec:
  author: "Frontend Maintainer <frontend@example.com>"
  config:
    cmd: ["/usr/bin/start", "--help"]
    entrypoint: ["/bin/sh"]
    env:
      PATH: "/usr/local/bin"
      NODE_ENV: "production"
    expose: ["8080", "443"]
    labels:
      app: "frontend"
    user: "node"
    workingDir: "/app"
```

(S013)

Per-image configuration takes precedence over global. String values are overwritten; multi-valued directives are merged. (S013)

## Available `config` directives

| Directive | Value | Description |
|-----------|-------|-------------|
| `cmd` | `[string, ...]` | Set CMD |
| `entrypoint` | `[string, ...]` | Set ENTRYPOINT |
| `env` | `{ name: value, ... }` | List of environment variables to add |
| `expose` | `[string, ...]` | Set exposed ports |
| `healthcheck` | `{ test, interval, retries }` | Healthcheck configuration |
| `labels` | `{ name: value, ... }` | List of labels to add |
| `stopSignal` | `string` | Set STOPSIGNAL |
| `user` | `string` | Set USER |
| `volumes` | `[string, ...]` | List of volumes to add |
| `workingDir` | `string` | Set WORKDIR |
| `removeEnv` | `[string, /regex/, ...]` | List of environment variables to remove |
| `removeLabels` | `[string, /regex/, ...]` | List of labels to remove |
| `removeVolumes` | `[string, ...]` | List of volumes to remove |
| `keepEssentialWerfLabels` | `bool` | Do not remove werf labels |
| `clearCmd` | `bool` | Remove CMD |
| `clearEntrypoint` | `bool` | Remove ENTRYPOINT |
| `clearUser` | `bool` | Remove USER |
| `clearWorkingDir` | `bool` | Remove WORKDIR |

(S013)

## Directives outside `config`

- `author` — author of the image (string)
- `clearHistory` — remove all image build history (bool)

(S013)

---

See also: [werf.yaml image environment variables](./werf-yaml-image-env.md) for details on `env` and `removeEnv`; [werf.yaml environment variables](./werf-yaml-env.md) for `.Env` and `env()` template functions.