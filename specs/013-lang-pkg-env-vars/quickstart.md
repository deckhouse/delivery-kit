# Quickstart: lang-pkg-env-vars

**Branch**: `013-lang-pkg-env-vars` | **Date**: 2026-08-03 | **Spec**: [spec.md](spec.md) | **Data Model**: [data-model.md](data-model.md)

## Overview

This guide describes how to validate the language package manager env vars feature end-to-end. The feature wires `packages[].env` into the runtime shell commands for 9 language package manager types, using the same inline prefix mechanism as `os-pm`.

## Prerequisites

- Go 1.24.10+
- `task` command (build/test orchestrator)
- Docker (for e2e tests)
- A Kubernetes cluster with kind (for full e2e)
- This branch checked out: `013-lang-pkg-env-vars`

## Validation Scenarios

### Scenario 1: Unit tests — env vars appear in generated commands (Highest priority)

The fastest validation. Run the config package unit tests to verify that `GeneratePackagesCommands` produces env-prefixed commands for each language type.

```bash
# Run all config package tests
task test:unit -- paths="./pkg/config/..."
```

**Expected outcomes:**
- Tests for each language type (`go-mod`, `python-uv`, `python-pip`, `python-poetry`, `rust-cargo`, `javascript-npm`, `javascript-yarn`, `javascript-pnpm`, `lua-rock`) pass with env vars present in generated commands.
- Tests for backward compatibility (nil/empty env → no prefix) pass.
- "ignores env" tests from the previous behavior fail until updated — this is the **expected test change** this feature introduces.

### Scenario 2: Config parsing — env var validation

Verify that invalid env var names are rejected at config parse time for language package types.

```bash
task test:unit -- paths="./pkg/config/" -run "rawPackagesDirective"
```

**Expected outcomes:**
- Env var names like `1INVALID`, `has=equals`, `with spaces` produce parse errors.
- Valid names like `GOPROXY`, `PIP_INDEX_URL`, `CARGO_NET_RETRY` are accepted.

### Scenario 3: E2E — language package with private registry auth (P1)

Create a werf.yaml with a language package that depends on a private registry and verify authentication via env vars.

**Setup:**
- A werf.yaml with `javascript-npm` package and `npm_config__authtoken` in `packages[].env`
- Alternatively, use `python-pip` with `PIP_INDEX_URL` pointing to a private PyPI mirror

**Command:**
```bash
# Run targeted e2e tests for this feature
task test:e2e -- labelFilter="lang-pkg-env-vars"
```

**Expected outcome:**
- The package manager authenticates to the private registry using the provided env vars.
- Build logs contain the env var key=value pairs (per FR-005).
- The container image includes successfully installed packages.

### Scenario 4: E2E — backward compatibility (no env)

Verify that language packages without `env` work exactly as before.

**Setup:**
- An existing werf.yaml with a `go-mod` package and no `env` field (or empty `env: {}`)
- The same project previously tested without this feature

**Expected outcome:**
- Build succeeds identically to pre-feature behavior.
- No env prefix appears in the generated command.

### Scenario 5: E2E — proxy support (P3)

Verify that language package managers use proxy settings when `HTTP_PROXY`/`HTTPS_PROXY` are set.

**Setup:**
- A werf.yaml with any language package manager
- `HTTP_PROXY` and `HTTPS_PROXY` set in `packages[].env`
- An intercepted proxy server in the test environment

**Expected outcome:**
- Package download traffic is routed through the configured proxy.

### Scenario 6: Build smoke test

Verify the feature compiles cleanly.

```bash
task build
```

**Expected outcome:**
- Binary builds without errors.

### Scenario 7: Lint check

Verify the code meets project quality standards.

```bash
task lint:golangci-lint -- golangciPaths="./pkg/config/..."
```

**Expected outcome:**
- No linting errors or warnings.

## Detailed Test Plan Reference

### Unit tests to verify (in `pkg/config/packages_commands_test.go`)

| Test | Language Type | Env Var Example | Expected Command Output |
|------|---------------|-----------------|------------------------|
| GoMod with GOPROXY | `go-mod` | `GOPROXY=direct` | `GOPROXY="direct" cd "/app" && go mod download` |
| PythonPip with PIP_INDEX_URL | `python-pip` | `PIP_INDEX_URL=http://pypi:8080` | `PIP_INDEX_URL="http://pypi:8080" cd "/app" && pip install --no-cache-dir -r "requirements.txt"` |
| RustCargo with CARGO_NET_RETRY | `rust-cargo` | `CARGO_NET_RETRY=3` | `CARGO_NET_RETRY="3" cd "/app" && cargo fetch` |
| JavaScriptNpm with npm_config | `javascript-npm` | `npm_config__authtoken=token` | `npm_config__authtoken="token" cd "/app" && npm ci` |
| JavaScriptYarn with yarn config | `javascript-yarn` | `YARN_ENABLE_IMMUTABLE_INSTALLS=false` | `YARN_ENABLE_IMMUTABLE_INSTALLS="false" cd "/app" && yarn install --frozen-lockfile` |
| JavaScriptPnpm with pnpm config | `javascript-pnpm` | `PNPM_HOME=/custom/path` | `PNPM_HOME="/custom/path" cd "/app" && pnpm install --frozen-lockfile` |
| PythonUV with UV config | `python-uv` | `UV_EXTRA_INDEX_URL=http://pypi:8080` | `UV_EXTRA_INDEX_URL="http://pypi:8080" cd "/app" && uv sync --frozen` |
| PythonPoetry with poetry config | `python-poetry` | `POETRY_HTTP_BASIC_MYREGISTRY_USERNAME=user` | `POETRY_HTTP_BASIC_MYREGISTRY_USERNAME="user" cd "/app" && poetry sync --no-root` |
| LuaRock with luarocks config | `lua-rock` | `LUAROCKS_PROXY=http://proxy:8080` | `LUAROCKS_PROXY="http://proxy:8080" cd "/app" && luarocks install --only-deps "rockspec"` |

## Contracts

See [data-model.md](data-model.md) for the full entity model and relationships. The key contract to validate is:

```
InstallCmd(workdir, specFile, specList, env) → shell command string
    where env != nil → formatEnvVars(env) + " " + original_install_cmd
    where env == nil → original_install_cmd (unchanged)