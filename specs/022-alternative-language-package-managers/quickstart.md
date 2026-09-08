# Quickstart Validation Guide

## Prerequisites

- Linux environment with Docker, the prepared e2e infrastructure, and network access to npm/PyPI.
- Repository dependencies installed as expected by the project task runner.
- A builder image for each fixture that contains npm or pip but does not contain Yarn, pnpm, uv, or Poetry respectively; Python fixtures also need `python3 -m venv` support.

## Configuration checks

Add an alternative directive with an exact version:

```yaml
packages:
  - type: javascript-pnpm
    workdir: /app
    version: 9.15.4
```

Verify that parsing succeeds. Then verify that each of the following fails before build execution:

- omitted `version`;
- `version: latest`;
- `version: '1.2'`;
- `version: '>=1.2.3'`;
- `version` on `javascript-npm` or `python-pip`.

The complete wire contract is in [`contracts/configuration.md`](contracts/configuration.md), and lifecycle invariants are in [`data-model.md`](data-model.md).

## Isolated command decomposition

The generated command sequence must use one complete `if ... then ... else ... fi` block per alternative ecosystem. The examples below show one representative manager for each ecosystem: Yarn for JavaScript and uv for Python. pnpm and Poetry follow the same respective templates. The `then` branch rejects a pre-installed alternative manager; the `else` branch keeps scope creation, bootstrap, version verification, dependency installation, and cleanup together, without persistent `PATH` mutation:

```sh
if command -v yarn >/dev/null 2>&1; then
  echo 'yarn must not be pre-installed' >&2
  exit 1
else
  set -e
  scope=$(mktemp -d)
  npm install --prefix "$scope" --no-save --package-lock=false yarn@1.22.22
  "$scope/bin/yarn" --version | grep -Fx '1.22.22'
  "$scope/bin/yarn" install --frozen-lockfile
  rm -rf "$scope"
fi

if command -v uv >/dev/null 2>&1; then
  echo 'uv must not be pre-installed' >&2
  exit 1
else
  set -e
  scope=$(mktemp -d)
  python3 -m venv "$scope"
  "$scope/bin/python" -m pip install --no-cache-dir uv==0.8.17
  "$scope/bin/uv" --version | grep -F '0.8.17'
  "$scope/bin/uv" sync --frozen
  rm -rf "$scope"
fi
```

Every ecosystem uses the same complete conditional shape. Each lifecycle command occupies its own line under fail-fast shell execution: bootstrap or dependency failures prevent later steps, cleanup runs only after successful dependency installation, and cleanup failures remain visible. A pre-installed manager is rejected and never removed.

## Unit validation

Use the repository task runner, not raw Go commands:

```sh
task test:unit paths="./pkg/config/..."
task test:unit paths="./pkg/build/stage/..."
```

The tests should compare each complete generated lifecycle snippet, including pre-installed-manager rejection, ephemeral bootstrap, exact-version verification, dependency execution, cleanup placement, version propagation, cache checksum changes, primary-manager compatibility, cleanup failure, and independent directives.

## E2E validation

Run each dedicated manager scenario:

```sh
task test:e2e paths="./test/e2e/sbom/..." labelFilter="yarn"
task test:e2e paths="./test/e2e/sbom/..." labelFilter="pnpm"
task test:e2e paths="./test/e2e/sbom/..." labelFilter="uv"
task test:e2e paths="./test/e2e/sbom/..." labelFilter="poetry"
```

Expected outcomes for every scenario:

1. the builder image lacks the selected alternative manager but provides npm or pip;
2. a builder image containing the selected alternative manager is rejected;
3. the exact configured manager version is installed in a unique temporary npm prefix or Python virtual environment;
4. the locked project dependencies install successfully through the temporary manager executable selected by absolute path;
5. the resulting image does not retain the temporary prefix or virtual environment;
6. `werf sbom get app` contains the fixture dependency from its manifest/lock file.

For a full feature validation after implementation, run the required project gates in order: `task format`, `task build`, `task deps:install:golangci-lint`, `task lint`, `task test:unit`, the four scoped e2e commands above, and `task test:integration`.
