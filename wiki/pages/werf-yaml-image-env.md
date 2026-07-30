---
title: "werf.yaml image environment variables"
type: concept
sources: [S013]
updated: 2026-07-30
---

The `imageSpec.config.env` directive sets environment variables in the final image's OCI configuration. This is separate from the `.Env` template variable and `env()` template function used in `werf.yaml` template processing. (S013)

## `imageSpec.config.env` — setting environment variables

To set environment variables in the image, use `imageSpec.config.env`:

```yaml
image: backend
from: alpine:3.21
imageSpec:
  config:
    env:
      PATH: "/usr/local/bin"
      NODE_ENV: "production"
```

(S013)

### Referencing existing image environment variables

You can reference environment variables already present in the base image using the `${ENV_NAME}` syntax:

```yaml
image: backend
from: alpine:3.21
imageSpec:
  config:
    env:
      PATH: "${PATH}:/app/bin"
```

(S013)

### Limitation: vars declared in imageSpec cannot reference each other

Environment variables declared in the same `imageSpec.config.env` block cannot reference each other. For example, `CUSTOM: "${MY_ENV}"` will result in an empty value for `CUSTOM`, not `MY_VAL`. This behavior is consistent with Docker's handling of `ENV`. (S013)

## `imageSpec.config.removeEnv` — removing environment variables

To remove environment variables from the image, use `imageSpec.config.removeEnv`:

```yaml
imageSpec:
  config:
    removeEnv:
      - "DEBUG"
      - "/^TEMP_.*$/"
```

String values match exact names; regex patterns are enclosed in `/`. (S013)

## `docker.ENV` — deprecated alternative for Stapel images

For Stapel-based images, the deprecated `docker.ENV` directive can also be used:

```yaml
image: app
from: ubuntu:22.04
docker:
  ENV:
    PATH: "/app/bin"
```

This directive is incompatible with `imageSpec` and is deprecated. (S013)

## Global configuration does NOT include env

The global `build.imageSpec.config` section does not support `env` or `removeEnv` — only `labels`, `removeLabels`, and `keepEssentialWerfLabels` are available globally. Environment variables must be configured per-image. (S013)

---

See also: [werf.yaml environment variables](./werf-yaml-env.md) for `.Env` template variable and `env()` template function; [werf.yaml image configuration spec](./werf-yaml-image-spec.md) for the full `imageSpec` reference.