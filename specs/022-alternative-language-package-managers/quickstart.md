# Quickstart Validation Guide

## Prerequisites

- Linux environment with Docker, the prepared e2e infrastructure, and network access to npm/PyPI.
- Repository dependencies installed as expected by the project task runner.
- A builder image for each fixture that contains npm or pip but does not contain Yarn, pnpm, uv, or Poetry respectively.

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

## Unit validation

Use the repository task runner, not raw Go commands:

```sh
task test:unit paths="./pkg/config/..."
task test:unit paths="./pkg/build/stage/..."
```

The tests should cover exact command ordering, version propagation, cache checksum changes, primary-manager compatibility, pre-existing-manager rejection, cleanup failure, and independent directives.

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
2. the exact configured manager version is installed globally through npm or into the Python system interpreter through pip;
3. the locked project dependencies install successfully through the global manager executable;
4. the resulting image does not retain the temporary global manager package;
5. `werf sbom get app` contains the fixture dependency from its manifest/lock file.

For a full feature validation after implementation, run the required project gates in order: `task format`, `task build`, `task deps:install:golangci-lint`, `task lint`, `task test:unit`, the four scoped e2e commands above, and `task test:integration`.
