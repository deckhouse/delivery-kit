# Quickstart: os-pm File-Based Syntax Validation

## Prerequisites

- Go 1.24.10
- Working werf development environment (`task build`)
- Git repository with test fixture files

## Setup

1. Ensure `task` commands are available:
   ```shell
   go install github.com/go-task/task/v3/cmd/task@latest
   ```

2. Build the project (from repo root):
   ```shell
   task build
   ```

## Validation Scenarios

### Scenario 1: Default spec/lock configuration

**What it validates**: A minimal `os-pm` directive (without explicit spec/lock) uses defaults `pm.yaml` and `pm.lock` at repo root.

**Setup**:
1. Create a test `werf.yaml` with:
   ```yaml
   image: test-image
   from: ubuntu:22.04
   packages:
     - type: os-pm
   ```

2. Create `pm.yaml` at repo root with test packages.
3. Create `pm.lock` at repo root (e.g., via `pm lock`).

**Run**:
```shell
task test:unit -- paths="./pkg/config/..." -run "TestRawPackagesDirective"
```

**Expected outcome**: The config unmarshal succeeds. `PackagesDirective` has `FileBased.Spec = "pm.yaml"` and `FileBased.Lock = "pm.lock"`. The generated command is `pm sync --from pm.lock` (preceded by container factory version snapshot commands).

### Scenario 2: Custom spec/lock paths

**What it validates**: Explicit `spec` and `lock` override defaults.

**Setup**: `werf.yaml` with:
```yaml
packages:
  - type: os-pm
    spec: custom-pm.yaml
    lock: custom.lock
```

**Run**:
```shell
task test:unit -- paths="./pkg/config/..." -run "TestRawPackagesDirective"
```

**Expected outcome**: `FileBased.Spec = "custom-pm.yaml"` and `FileBased.Lock = "custom.lock"`. The generated command is `pm sync --from custom.lock`.

### Scenario 3: Reject old inline syntax

**What it validates**: The old `spec: [curl, jq]` syntax is rejected at config parse time.

**Setup**: `werf.yaml` with:
```yaml
packages:
  - type: os-pm
    spec: [curl, jq]
```

**Run**:
```shell
task test:unit -- paths="./pkg/config/..." -run "rawPackagesDirective"
```

**Expected outcome**: Config parse error: `"unsupported packages spec type []interface{} for type "os-pm"; spec must be a string"`.

### Scenario 4: Reject workdir

**What it validates**: `workdir` is rejected for `os-pm`.

**Setup**: `werf.yaml` with:
```yaml
packages:
  - type: os-pm
    workdir: /app
```

**Run**:
```shell
task test:unit -- paths="./pkg/config/..." -run "rawPackagesDirective"
```

**Expected outcome**: Validation error: `"workdir is not supported for type "os-pm""`.

### Scenario 5: Missing pm.lock

**What it validates**: Build fails when `pm.yaml` exists but `pm.lock` is missing.

**Setup**:
1. Create `pm.yaml` at repo root.
2. Do NOT create `pm.lock`.

**Expected outcome**: When config is parsed and build runs, the build fails with a clear error: `"pm.lock not found at <path>. Run 'pm lock' in your repository to generate the lock file, commit it, and retry."`

### Scenario 6: Env vars preserved

**What it validates**: Environment variables specified in `packages.env` are passed to the `pm sync` command.

**Setup**: `werf.yaml` with:
```yaml
packages:
  - type: os-pm
    env:
      HTTP_PROXY: "http://proxy.example.com:8080"
```

**Run**:
```shell
task test:unit -- paths="./pkg/config/..." -run "GeneratePackagesCommands"
```

**Expected outcome**: The generated command includes `HTTP_PROXY="http://proxy.example.com:8080"` before `pm sync --from pm.lock`.

### Scenario 7: SBOM cataloger registration

**What it validates**: The `os-pm` ecosystem entry registers a `CatalogerName` that produces correct source paths.

**Run**:
```shell
task test:unit -- paths="./pkg/sbom/managedinput/..." -run "ToCatalogers"
```

**Expected outcome**: When `os-pm` packages are present, `ToCatalogers()` returns a cataloger with name `"os-pm-lock-cataloger"`, source paths `["pm.yaml", "pm.lock"]`, and empty workdir.

### Scenario 8: No os-pm packages → no pm sync

**What it validates**: Build without any `os-pm` directive produces no `pm sync` commands and skips os-pm SBOM processing.

**Setup**: `werf.yaml` without any `packages` directive (or with only non-`os-pm` types).

**Run**:
```shell
task test:unit -- paths="./pkg/config/..." -run "GeneratePackagesCommands"
```

**Expected outcome**: `GeneratePackagesCommands()` returns empty slice. No `pm sync` command is generated.

### Scenario 9: All tests pass

**Full validation**:
```shell
task test:unit -- paths="./pkg/config/..."
task test:unit -- paths="./pkg/sbom/managedinput/..."
task test:unit -- paths="./pkg/build/stage/..."
```

**Expected outcome**: All unit tests pass with updated file-based syntax.

## Data Model Reference

For details on struct fields, validation rules, and relationships, see [data-model.md](data-model.md).

## Contracts Reference

For configuration schema, file conventions, and SBOM integration contracts, see [contracts/README.md](contracts/README.md).