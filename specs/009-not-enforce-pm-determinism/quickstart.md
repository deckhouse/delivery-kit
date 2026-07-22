# Quickstart: Not Enforce pm Determinism

**Phase**: Phase 1 — Design & Contracts
**Date**: 2026-07-22
**Spec**: `specs/009-not-enforce-pm-determinism/spec.md`

## Overview

This guide documents validation scenarios to verify the revert is working correctly. See [spec.md](../spec.md) for the full specification, [data-model.md](../data-model.md) for data structures, and [contracts/contracts.md](contracts.md) for configuration contracts.

## Prerequisites

- Go 1.24.10
- Task CLI
- Access to a container build environment (Buildah-based)

## Validation Scenarios

### Scenario 1: Inline packages generate correct install commands

**Setup**: Create a minimal `werf.yaml` with `os-pm` inline packages.

```yaml
configVersion: 1
project: test-inline-pm
---
image: app
from: alpine:latest
packages:
  - type: os-pm
    spec:
      - curl==8.12.1
      - jq
```

**Expected outcome**: The build stage generates a single `pm install curl==8.12.1 jq` command with inline environment variables (not `pm sync --from ...`).

**Command**:
```bash
task test:unit -- -run TestOsPmSingleCommand ./pkg/config/...
```

---

### Scenario 2: Empty `spec` list rejected at config validation

**Setup**: Create a `werf.yaml` with an empty `spec` list.

```yaml
packages:
  - type: os-pm
    spec: []
```

**Expected outcome**: Configuration validation fails with an error indicating `spec` must contain at least one package name for `os-pm`.

---

### Scenario 3: `workdir` is rejected for `os-pm`

**Setup**: Create a `werf.yaml` with `workdir` specified for `os-pm`.

```yaml
packages:
  - type: os-pm
    workdir: /app
    spec:
      - curl
```

**Expected outcome**: Configuration validation fails with an error indicating `workdir` is not a valid field for `os-pm`.

**Command**:
```bash
task test:unit -- -run TestOsPmRejectsWorkdir ./pkg/config/...
```

---

### Scenario 4: No `packages` directive produces no pm commands

**Setup**: Create a `werf.yaml` with no `packages` directive at all.

**Expected outcome**: No `pm install` or `pm sync` command is generated. The SBOM step skips os-pm processing entirely.

**Command**:
```bash
task test:unit -- -run TestNoOsPmPackages ./pkg/build/...
```

---

### Scenario 5: SBOM collected via `pm info --installed --json`

**Setup**: Build an image with `os-pm` packages, then check the SBOM output.

**Expected outcome**: The SBOM contains package components collected from the `pm info --installed --json` command output captured during the build stage, not from a `pm.lock` file.

**Command**:
```bash
task test:unit -- -run TestOsPmSbomRuntime ./pkg/sbom/packages/os_pm/...
```

---

### Scenario 6: Full e2e smoke test

**Setup**: Run the os-pm e2e test suite.

**Command**:
```bash
task test:e2e -- -labelFilter="sbom && packages" ./test/e2e/sbom/...
```

**Expected outcome**: All e2e tests pass with updated expectations matching the inline model.

---

### Scenario 7: Both inline `packages` and `spec`/`lock` rejected as ambiguous

**Setup**: Create a `werf.yaml` specifying both.

```yaml
packages:
  - type: os-pm
    spec: [curl==8.12.1]
    lock: pm.lock
```

**Expected outcome**: Configuration validation fails with an ambiguity error — `spec` cannot be both a list (inline package names) and a string (file path) simultaneously.

---

### Scenario 8: Build with `go-mod` (non-os-pm) still works

**Setup**: Create a `werf.yaml` with a `go-mod` package type.

**Expected outcome**: `go-mod` packages are unaffected by the revert — they continue to use file-based spec+lock.

---

## Verification Commands

Run all unit tests for affected packages:

```bash
task test:unit paths="./pkg/..." -- -count=1
```

Run all e2e tests:

```bash
task test:e2e paths="./test/e2e/sbom/..." labelFilter="sbom && (packages || lifecycle || gost)"
```