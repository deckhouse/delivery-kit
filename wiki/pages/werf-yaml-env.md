---
title: "werf.yaml environment variables"
type: concept
sources: [S012]
updated: 2026-07-30
---

The `werf.yaml` template engine provides two mechanisms for working with environment-related values: the `.Env` template variable for multi-environment configuration and the `env` function for reading OS environment variables. (S012)

## `.Env` — multi-environment configuration

The `.Env` variable organizes configuration for several environments (testing, production, staging, etc.) and switches between them via the `--env=<environment_name>` CLI option. (S012)

In Helm templates the same value is available as `.Values.werf.env`. (S012)

## `env` — OS environment variable reader

The `env` function reads an OS environment variable:

```
{{ env "<ENV_NAME>" }}
{{ env "<ENV_NAME>" "default_value" }}
```

(S012)

By default, use of the `env` function is not allowed by giterminism — the giterminism configuration must explicitly permit it. (S012)

## `expandenv` not supported

The Sprig `expandenv` function is not supported in werf. (S012)

---

See also: [werf.yaml template engine](./werf-yaml-template-engine.md) for the full template engine reference.