# Quickstart: os-pm Environment Variables

This guide provides validation scenarios to verify the feature works end-to-end.

## Prerequisites

- Go 1.24.10
- `task` command (Task runner)
- Docker or Podman for local builds
- Access to a container registry (or use `--dev` mode)

## Setup

```bash
# From repo root
task build
```

## Validation Scenarios

### Scenario 1: Basic env var passthrough (os-pm)

**Goal**: Verify that env vars set in `packages[].env` appear in the `pm install` process.

1. Create a test `werf.yaml`:

```yaml
project: test-pm-env
configVersion: 1
---
image: test
from: alpine:3.18
packages:
  - type: os-pm
    spec:
      - curl
    env:
      CUSTOM_VAR: hello-world
```

2. Build the image and check build logs for the env var export:

```bash
werf build --dev
```

**Expected**: Build log contains `CUSTOM_VAR="hello-world"` before the `pm install` command (as inline env prefix).

---

### Scenario 2: DOCKER_CONFIG for private registries

**Goal**: Verify that `DOCKER_CONFIG` is passed to the package manager for authentication against private registries.

1. Create a test `werf.yaml` with a secret mount:

```yaml
project: test-pm-auth
configVersion: 1
---
image: test
from: alpine:3.18
secrets:
  - id: docker-config
    src: /path/to/docker-config.json
packages:
  - type: os-pm
    spec:
      - private-package-name
    env:
      DOCKER_CONFIG: /run/secrets/docker-config
```

2. Build the image:

```bash
werf build --dev
```

**Expected**: The package manager authenticates against the private registry and installs the package successfully.

---

### Scenario 3: Proxy environment variables

**Goal**: Verify that proxy env vars are passed to the package manager.

1. Create a test `werf.yaml`:

```yaml
project: test-pm-proxy
configVersion: 1
---
image: test
from: alpine:3.18
packages:
  - type: os-pm
    spec:
      - curl
    env:
      HTTP_PROXY: http://proxy.example.com:8080
      HTTPS_PROXY: http://proxy.example.com:8080
```

2. Build the image:

```bash
werf build --dev
```

**Expected**: Build log contains `HTTP_PROXY="http://proxy.example.com:8080" HTTPS_PROXY="http://proxy.example.com:8080"` before `pm install` (as inline env prefix). Package downloads are routed through the proxy.

---

### Scenario 4: Package manager behavior customization

**Goal**: Verify that `DEBIAN_FRONTEND` etc. change package manager behavior.

1. Create a test `werf.yaml`:

```yaml
project: test-pm-debconf
configVersion: 1
---
image: test
from: debian:bookworm
packages:
  - type: os-pm
    spec:
      - tzdata
    env:
      DEBIAN_FRONTEND: noninteractive
      TZ: Etc/UTC
```

2. Build the image:

```bash
werf build --dev
```

**Expected**: The tzdata package installs without interactive prompts, even though it normally shows a timezone selection dialog.

---

### Scenario 5: Empty env map (backward compatibility)

**Goal**: Verify that `env: {}` is treated the same as no `env`.

1. Create a test `werf.yaml`:

```yaml
project: test-pm-no-env
configVersion: 1
---
image: test
from: alpine:3.18
packages:
  - type: os-pm
    spec:
      - curl
    env: {}
```

2. Build the image:

```bash
werf build --dev
```

**Expected**: Build succeeds as if `env` was not specified. The `pm install` command runs without any custom env vars.

---

### Scenario 6: Invalid env var name (config parse error)

**Goal**: Verify that invalid names are rejected at config parse time.

1. Create a test `werf.yaml`:

```yaml
project: test-pm-invalid
configVersion: 1
---
image: test
from: alpine:3.18
packages:
  - type: os-pm
    spec:
      - curl
    env:
      1INVALID: value
```

2. Attempt to build:

```bash
werf build --dev
```

**Expected**: The build fails at config parse time with an error message like:
```
invalid environment variable name "1INVALID" in packages[0].env: must match POSIX naming pattern [a-zA-Z_][a-zA-Z0-9_]*
```

---

### Scenario 7: Non-os-pm type ignores env

**Goal**: Verify that `env` is silently ignored for non-os-pm package types.

1. Create a test `werf.yaml`:

```yaml
project: test-pm-other-type
configVersion: 1
---
image: test
from: alpine:3.18
packages:
  - type: go-mod
    spec: go.mod
    workdir: /app
    env:
      GOPROXY: http://proxy:8080
```

2. Attempt to build:

**Expected**: The config is parsed without errors. The `env` field is stored in the `PackagesDirective` but silently ignored at runtime (no env var prefix in the go-mod command).

---

### Running validation tests

```bash
# Format code
task format

# Build
task build

# Run unit tests (config package)
task test:unit paths="./pkg/config/..."

# Run all linters
task lint

# Run e2e tests (if available)
task test:e2e paths="./test/e2e/" labelFilter="os-pm"
```

## Detailed References

- [Data model](data-model.md) — entity definitions, validation rules, state transitions
- [YAML config contract](contracts/YAML-config-schema.md) — config schema specification
- [Go API contract](contracts/Go-API.md) — Go types and function signatures
- [Specification](spec.md) — full feature specification with user stories and edge cases